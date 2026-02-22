// unisa assembler
// two-pass: first pass finds labels, second pass emits bytes.
// supports comments with ;, labels with :, and directives (.org, .db)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// opcodes — must match unisa cpu/control_unit.h
#define OP_NOP  0x00
#define OP_HLT  0x01
#define OP_RET  0x02
#define OP_PUSH 0x03
#define OP_POP  0x04
#define OP_CLI  0x05
#define OP_STI  0x06
#define OP_RTI  0x07
#define OP_LDI  0x10
#define OP_LD   0x11
#define OP_ST   0x12
#define OP_MOV  0x13
#define OP_LDR  0x14
#define OP_STR  0x15
#define OP_ADD  0x20
#define OP_SUB  0x21
#define OP_AND  0x22
#define OP_OR   0x23
#define OP_XOR  0x24
#define OP_NOT  0x25
#define OP_SHL  0x26
#define OP_SHR  0x27
#define OP_CMP  0x28
#define OP_ADDI 0x29
#define OP_JMP  0x30
#define OP_JZ   0x31
#define OP_JNZ  0x32
#define OP_JC   0x33
#define OP_JNC  0x34
#define OP_CALL 0x40

#define MAX_LINES  4096
#define MAX_LINE   256
#define MAX_LABELS 256

// --- labels ---

typedef struct {
    char name[64];
    int addr;
} Label;

static Label labels[MAX_LABELS];
static int num_labels = 0;

static void add_label(const char *name, int addr) {
    strncpy(labels[num_labels].name, name, 63);
    labels[num_labels].addr = addr;
    num_labels++;
}

static int find_label(const char *name) {
    for (int i = 0; i < num_labels; i++)
        if (strcmp(labels[i].name, name) == 0)
            return labels[i].addr;
    fprintf(stderr, "unknown label: %s\n", name);
    exit(1);
}

// --- output buffer ---

static unsigned char output[65536];
static int out_pos = 0;
static int out_max = 0; // highest position written (for .org gaps)

static void emit(unsigned char byte) {
    output[out_pos++] = byte;
    if (out_pos > out_max) out_max = out_pos;
}

// --- string helpers ---

static void trim(char *s) {
    char *start = s;
    while (*start && isspace(*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    int len = strlen(s);
    while (len > 0 && isspace(s[len - 1])) s[--len] = '\0';
}

static void to_upper(char *s) {
    for (int i = 0; s[i]; i++)
        s[i] = toupper(s[i]);
}

// --- parsing ---

static int parse_reg(const char *s) {
    if ((s[0] == 'R' || s[0] == 'r') && s[1] >= '0' && s[1] <= '7')
        return s[1] - '0';
    fprintf(stderr, "bad register: %s\n", s);
    exit(1);
}

static int parse_number(const char *s) {
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        return (int)strtol(s, NULL, 16);
    return (int)strtol(s, NULL, 10);
}

// number or label — figures it out
static int parse_value(const char *s) {
    if (isdigit(s[0]))
        return parse_number(s);
    char upper[64];
    strncpy(upper, s, 63);
    upper[63] = '\0';
    to_upper(upper);
    return find_label(upper);
}

// --- encoding helpers ---

static void emit_1byte(int op) {
    emit(op);
}

static void emit_reg_reg(int op, int rd, int rs) {
    emit(op);
    emit((rd & 7) | ((rs & 7) << 3));
    emit(0);
}

static void emit_reg_imm(int op, int rd, int imm) {
    emit(op);
    emit(rd & 7);
    emit(imm & 0xFF);
}

static void emit_reg_reg_imm(int op, int rd, int rs, int imm) {
    emit(op);
    emit((rd & 7) | ((rs & 7) << 3));
    emit(imm & 0xFF);
}

static void emit_reg_addr(int op, int rd, int addr) {
    emit(op);
    emit((addr & 0xF8) | (rd & 7)); // register overlaps with low address bits
    emit((addr >> 8) & 0xFF);
}

static void emit_addr16(int op, int addr) {
    emit(op);
    emit(addr & 0xFF);
    emit((addr >> 8) & 0xFF);
}

static void emit_reg_only(int op, int rd) {
    emit(op);
    emit(rd & 7);
    emit(0);
}

// --- directive helpers ---
// .db supports: numbers (.db 0x48, 0x65), strings (.db "Hi"), or both (.db "Hi", 10)
// .org just sets the output position

// walk a .db argument list, either counting bytes or emitting them.
// mode 0 = count only (for pass 1), mode 1 = emit (for pass 2).
static int process_db(const char *args, int mode) {
    int count = 0;
    const char *p = args;
    while (*p) {
        while (*p && isspace(*p)) p++;
        if (*p == '\0') break;
        if (*p == '"') {
            p++;
            while (*p && *p != '"') {
                if (mode) emit((unsigned char)*p);
                count++;
                p++;
            }
            if (*p == '"') p++;
        } else {
            char token[64] = "";
            int ti = 0;
            while (*p && *p != ',' && ti < 63) token[ti++] = *p++;
            token[ti] = '\0';
            trim(token);
            if (token[0]) {
                if (mode) emit((unsigned char)parse_number(token));
                count++;
            }
        }
        if (*p == ',') p++;
    }
    return count;
}

// --- instruction size (pass 1 needs this) ---

static int instr_size(const char *m) {
    if (strcmp(m, "NOP") == 0 || strcmp(m, "HLT") == 0 || strcmp(m, "RET") == 0 ||
        strcmp(m, "CLI") == 0 || strcmp(m, "STI") == 0 || strcmp(m, "RTI") == 0)
        return 1;
    return 3;
}

// --- the actual assembler (pass 2) ---

static void assemble_line(char *line) {
    char mnem[32], a1[64] = "", a2[64] = "";

    // strip comments and whitespace
    char *comment = strchr(line, ';');
    if (comment) *comment = '\0';
    trim(line);
    if (line[0] == '\0') return;
    if (line[strlen(line) - 1] == ':') return; // label, already handled

    // directives — handle before uppercasing since .db strings are case-sensitive
    if (line[0] == '.') {
        char dir[32], rest[MAX_LINE] = "";
        sscanf(line, "%31s %[^\n]", dir, rest);
        to_upper(dir);
        if (strcmp(dir, ".ORG") == 0) {
            trim(rest);
            out_pos = parse_number(rest);
            return;
        }
        if (strcmp(dir, ".DB") == 0) {
            process_db(rest, 1);
            return;
        }
        fprintf(stderr, "unknown directive: %s\n", dir);
        exit(1);
    }

    sscanf(line, "%31s %63[^,], %63s", mnem, a1, a2);
    to_upper(mnem);
    trim(a1);
    trim(a2);

    // 1-byte instructions
    if (strcmp(mnem, "NOP") == 0) { emit_1byte(OP_NOP); return; }
    if (strcmp(mnem, "HLT") == 0) { emit_1byte(OP_HLT); return; }
    if (strcmp(mnem, "RET") == 0) { emit_1byte(OP_RET); return; }
    if (strcmp(mnem, "CLI") == 0) { emit_1byte(OP_CLI); return; }
    if (strcmp(mnem, "STI") == 0) { emit_1byte(OP_STI); return; }
    if (strcmp(mnem, "RTI") == 0) { emit_1byte(OP_RTI); return; }

    // stack
    if (strcmp(mnem, "PUSH") == 0) { emit_reg_only(OP_PUSH, parse_reg(a1)); return; }
    if (strcmp(mnem, "POP") == 0)  { emit_reg_only(OP_POP, parse_reg(a1)); return; }

    // reg, reg operations
    if (strcmp(mnem, "ADD") == 0) { emit_reg_reg(OP_ADD, parse_reg(a1), parse_reg(a2)); return; }
    if (strcmp(mnem, "SUB") == 0) { emit_reg_reg(OP_SUB, parse_reg(a1), parse_reg(a2)); return; }
    if (strcmp(mnem, "AND") == 0) { emit_reg_reg(OP_AND, parse_reg(a1), parse_reg(a2)); return; }
    if (strcmp(mnem, "OR") == 0)  { emit_reg_reg(OP_OR,  parse_reg(a1), parse_reg(a2)); return; }
    if (strcmp(mnem, "XOR") == 0) { emit_reg_reg(OP_XOR, parse_reg(a1), parse_reg(a2)); return; }
    if (strcmp(mnem, "MOV") == 0) { emit_reg_reg(OP_MOV, parse_reg(a1), parse_reg(a2)); return; }
    if (strcmp(mnem, "CMP") == 0) { emit_reg_reg(OP_CMP, parse_reg(a1), parse_reg(a2)); return; }

    // unary — only uses rd
    if (strcmp(mnem, "NOT") == 0) { emit_reg_only(OP_NOT, parse_reg(a1)); return; }
    if (strcmp(mnem, "SHL") == 0) { emit_reg_only(OP_SHL, parse_reg(a1)); return; }
    if (strcmp(mnem, "SHR") == 0) { emit_reg_only(OP_SHR, parse_reg(a1)); return; }

    // reg, immediate
    if (strcmp(mnem, "LDI") == 0)  { emit_reg_imm(OP_LDI,  parse_reg(a1), parse_value(a2)); return; }
    if (strcmp(mnem, "ADDI") == 0) { emit_reg_imm(OP_ADDI, parse_reg(a1), parse_value(a2)); return; }

    // memory — watch out, register field overlaps with address low bits
    if (strcmp(mnem, "LD") == 0) { emit_reg_addr(OP_LD, parse_reg(a1), parse_value(a2)); return; }
    if (strcmp(mnem, "ST") == 0) { emit_reg_addr(OP_ST, parse_reg(a1), parse_value(a2)); return; }

    // indexed memory — LDR Rd, Rs, page / STR Rd, Rs, page
    if (strcmp(mnem, "LDR") == 0 || strcmp(mnem, "STR") == 0) {
        char r1[16], r2[16], r3[64];
        sscanf(line, "%*s %[^,], %[^,], %63s", r1, r2, r3);
        trim(r1); trim(r2); trim(r3);
        int op = (strcmp(mnem, "LDR") == 0) ? OP_LDR : OP_STR;
        emit_reg_reg_imm(op, parse_reg(r1), parse_reg(r2), parse_value(r3));
        return;
    }

    // jumps and calls
    if (strcmp(mnem, "JMP") == 0)  { emit_addr16(OP_JMP,  parse_value(a1)); return; }
    if (strcmp(mnem, "JZ") == 0)   { emit_addr16(OP_JZ,   parse_value(a1)); return; }
    if (strcmp(mnem, "JNZ") == 0)  { emit_addr16(OP_JNZ,  parse_value(a1)); return; }
    if (strcmp(mnem, "JC") == 0)   { emit_addr16(OP_JC,   parse_value(a1)); return; }
    if (strcmp(mnem, "JNC") == 0)  { emit_addr16(OP_JNC,  parse_value(a1)); return; }
    if (strcmp(mnem, "CALL") == 0) { emit_addr16(OP_CALL,  parse_value(a1)); return; }

    fprintf(stderr, "unknown instruction: %s\n", mnem);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s input.asm output.bin\n", argv[0]);
        return 1;
    }

    FILE *f = fopen(argv[1], "r");
    if (!f) { fprintf(stderr, "can't open %s\n", argv[1]); return 1; }

    char lines[MAX_LINES][MAX_LINE];
    int num_lines = 0;
    while (fgets(lines[num_lines], MAX_LINE, f) && num_lines < MAX_LINES)
        num_lines++;
    fclose(f);

    // pass 1: find all the labels and where they point
    int addr = 0;
    for (int i = 0; i < num_lines; i++) {
        char line[MAX_LINE];
        strncpy(line, lines[i], MAX_LINE);
        char *c = strchr(line, ';');
        if (c) *c = '\0';
        trim(line);
        if (line[0] == '\0') continue;

        int len = strlen(line);
        if (line[len - 1] == ':') {
            line[len - 1] = '\0';
            to_upper(line);
            add_label(line, addr);
            continue;
        }

        // directives
        if (line[0] == '.') {
            char dir[32], rest[MAX_LINE] = "";
            sscanf(line, "%31s %[^\n]", dir, rest);
            to_upper(dir);
            if (strcmp(dir, ".ORG") == 0) {
                trim(rest);
                addr = parse_number(rest);
            } else if (strcmp(dir, ".DB") == 0) {
                addr += process_db(rest, 0);
            }
            continue;
        }

        char m[32];
        sscanf(line, "%31s", m);
        to_upper(m);
        addr += instr_size(m);
    }

    // pass 2: actually assemble
    for (int i = 0; i < num_lines; i++)
        assemble_line(lines[i]);

    // write it out
    FILE *out = fopen(argv[2], "wb");
    if (!out) { fprintf(stderr, "can't write to %s\n", argv[2]); return 1; }
    fwrite(output, 1, out_max, out);
    fclose(out);

    printf("assembled %d bytes\n", out_max);
    return 0;
}
