#!/usr/bin/env python3
"""Instruction bytes from open-source assembly repositories, assembled with AS.

Builds code classes for CPUs whose code is mostly hand-written assembly and
for which no compiler corpus exists. A PROFILE names the CPU:

  8085    Intel 8080/8085 (`i8085` class). MAME runs `pp.u9` (Status Games
          Planet Patrol, misc/statriv2.cpp) on an I8085A, and the Z80 class
          does not read it.
  68hc11  Motorola 68HC11 (`hc11` class): ECU dumps in the fw1 set start
          with HC11 register-block set-up (`STAA $103D`, the INIT register).
  80196   Intel MCS-96 / 80C196 (`mcs96` class): Bosch Motronic ECU dumps.
  68000   Motorola 68000 (`m68k` class): its other samples are compiled
          (Debian m68k, GCC objects), while arcade and console system ROMs
          are hand-written; the Neo-Geo `vs-bios.rom` read at 0.5-0.8 b/B
          margins. Code assembled for another CPU (`CPU Z80` sound
          drivers) is dropped.

For each profile:

1. each repository in REPOS (TSV: `owner/name`, SPDX license, branch) is
   pinned and downloaded by github_repos.py;
2. every source with one of the profile's suffixes is assembled with the
   Macro Assembler AS (asl) for the profile's CPU (`-cpu`; a source's own
   `CPU` directive wins), with a listing; sources that do not assemble
   (other assemblers' directives, missing includes) are skipped. For the
   68HC11 and the 68000, full-line `*` comments are first rewritten to `;`
   comments; for the 68000, asm68k/Devpac local labels are renamed;
3. only the bytes of listing lines whose mnemonic is an instruction of the
   profile are kept, in listing order: data directives, strings and tables
   are dropped, as raw-ext/PROVENANCE.md asks (code only);
4. the programs of one repository become one sample, OUT/<owner>__<name>.bin.

Usage:
    asl_asm_corpus.py --asl PATH_TO_ASL --profile {8085,68hc11,80196,68000} REPOS WORK OUT PROVENANCE
"""
import argparse
import dataclasses
import hashlib
import importlib.util
import os
import re
import subprocess

# Loaded by path: `python3 -I` keeps the script directory off sys.path.
_spec = importlib.util.spec_from_file_location(
    "github_repos", os.path.join(os.path.dirname(os.path.abspath(__file__)), "github_repos.py"))
github_repos = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(github_repos)

ASSEMBLE_TIMEOUT_SECONDS = 10

# Width of the bytes field of an asl listing line (see LISTING_LINE): bytes
# for byte-addressed CPUs ("3E 12"), 16-bit words for the 68000 ("4E75"),
# measured on asl 1.42 Bld 312 listings.
BYTE_LISTING_FIELD = 27
WORD_LISTING_FIELD = 23


@dataclasses.dataclass(frozen=True)
class Profile:
    cpu: str
    """asl `-cpu` name (asl calls the 68HC11 `6811`)."""
    suffixes: tuple
    """Source file suffixes, lower case."""
    mnemonics: frozenset
    """Instruction mnemonics, lower case: lines with other mnemonics are not code."""
    star_comments: bool = False
    """Whether sources use Motorola full-line `*` comments, which asl rejects:
    they are rewritten to `;` comments in the downloaded tree first."""
    size_suffixes: bool = False
    """Whether mnemonics carry an operand-size suffix (`move.w`, `bra.s`),
    which is dropped before the mnemonic is looked up."""
    own_cpus: object = None
    """If set, a pattern for the `CPU` directive values of this profile's
    processor: listing lines after a `CPU` directive that selects another
    processor are not kept until one selects this profile's again, since
    their mnemonics can overlap (a Mega Drive game's Z80 sound driver,
    often in an included file)."""
    bytes_field: int = BYTE_LISTING_FIELD
    """Width of the listing's bytes field."""
    local_labels: bool = False
    """Whether sources use asm68k/Devpac local labels (`@loop`, `.loop`),
    which asl rejects: they are renamed per scope in the downloaded tree
    first (see rename_local_labels)."""


PROFILES = {
    # Intel 8080 mnemonics plus the 8085's RIM and SIM ("8080/8085 Assembly
    # Language Programming Manual", Intel 9800301).
    "8085": Profile("8085", (".asm", ".a85", ".s", ".mac", ".8085"), frozenset("""
mov mvi lxi lda sta lhld shld ldax stax xchg add adi adc aci sub sui sbb sbi
inr dcr inx dcx dad daa ana ani ora ori xra xri cmp cpi rlc rrc ral rar cma
cmc stc jmp jnz jz jnc jc jpo jpe jp jm call cnz cz cnc cc cpo cpe cp cm ret
rnz rz rnc rc rpo rpe rp rm rst pchl sphl xthl push pop in out ei di hlt nop
rim sim
""".split())),
    # "M68HC11 Reference Manual" (Motorola M68HC11RM/AD), instruction set
    # summary, plus the 6800/6801 spellings AS accepts (lda/sta/ora/eor with
    # an accumulator suffix are listed in their two-letter form).
    "68hc11": Profile("6811", (".asm", ".a11", ".s", ".hc11", ".68hc11", ".src", ".s11"), frozenset("""
aba abx aby adca adcb adda addb addd anda andb asl asla aslb asld asr asra asrb
bcc bclr bcs beq bge bgt bhi bhs bita bitb ble blo bls blt bmi bne bpl bra
brclr brn brset bset bsr bvc bvs cba clc cli clr clra clrb clv cmpa cmpb com
coma comb cpd cpx cpy daa dec deca decb des dex dey eora eorb fdiv idiv inc
inca incb ins inx iny jmp jsr ldaa ldab ldd lds ldx ldy lsl lsla lslb lsld lsr
lsra lsrb lsrd mul neg nega negb nop oraa orab psha pshb pshx pshy pula pulb
pulx puly rol rola rolb ror rora rorb rti rts sba sbca sbcb sec sei sev staa
stab std stop sts stx sty suba subb subd swi tab tap tba test tpa tst tsta tstb
tsx tsy txs tys wai xgdx xgdy
""".split()), star_comments=True),
    # "8XC196Kx, 8XC196Jx, 87C196CA Microcontroller Family User's Manual"
    # (Intel 272258), instruction set summary.
    "80196": Profile("80196", (".asm", ".a96", ".s", ".src", ".196"), frozenset("""
add addb addc addcb and andb bmov bmovi br clr clrb clrc clrvt cmp cmpb cmpl
dec decb di djnz djnzw dpts ei epts ext extb idlpd inc incb jbc jbs jc je jge
jgt jh jle jlt jnc jne jnh jnst jnv jnvt jst jv jvt lcall ld ldb ldbse ldbze
ljmp mul mulb mulu mulub neg negb nop norml not notb or orb pop popa popf push
pusha pushf ret rst scall setc shl shlb shll shr shra shrab shral shrb shrl
sjmp skip st stb sub subb subc subcb tijmp trap xch xchb xor xorb div divb divu
divub
""".split())),
    # "M68000 Family Programmer's Reference Manual" (Motorola M68000PM/AD),
    # integer instructions of the 68000/68010 with the condition-code forms
    # (Bcc, DBcc, Scc) spelled out, plus the BHS/BLO, DBRA and DBHS/DBLO
    # aliases that assemblers accept.
    "68000": Profile("68000", (".asm", ".s", ".68k", ".x68", ".a68", ".src", ".i", ".inc"), frozenset("""
abcd add adda addi addq addx and andi asl asr bchg bclr bset btst bra bsr
bcc bcs beq bge bgt bhi bhs ble blo bls blt bmi bne bpl bvc bvs chk clr cmp
cmpa cmpi cmpm dbcc dbcs dbeq dbf dbge dbgt dbhi dbhs dble dblo dbls dblt dbmi
dbne dbpl dbra dbt dbvc dbvs divs divu eor eori exg ext illegal jmp jsr lea
link lsl lsr move movea movec movem movep moveq moves muls mulu nbcd neg negx
nop not or ori pea reset rol ror roxl roxr rtd rte rtr rts sbcd scc scs seq sf
sge sgt shi shs sle slo sls slt smi sne spl st stop sub suba subi subq subx svc
svs swap tas trap trapv tst unlk
""".split()), star_comments=True, size_suffixes=True,
        own_cpus=re.compile(r"^(?:mc|m)?(?:680[0-6]0|68008|683\d\d)$|^cpu32$", re.IGNORECASE),
        bytes_field=WORD_LISTING_FIELD, local_labels=True),
}

# A listing line's `CPU` directive and the processor it selects (after an
# optional label).
CPU_DIRECTIVE = re.compile(r"^(?:\S*\s+|\s*)cpu\s+([\w.]+)", re.IGNORECASE)

# asl listing lines: `line/address : bytes  source`. The bytes field has a
# fixed width per CPU (Profile.bytes_field), so the source starts at a fixed
# column (a label sits in its first character). Continuation lines of a long
# statement carry an address and bytes but no line number or source.
LISTING_LINE = re.compile(r"^\s*(?:(\d+)(?:\(\d+\))?/)?\s*[0-9A-F]+ : ")
BYTE = re.compile(r"[0-9A-F]{2}")


def mnemonic(source, size_suffixes=False):
    """The first mnemonic of a source line, lower case, or None; without
    its operand-size suffix if `size_suffixes`."""
    text = source.split(";", 1)[0]
    if not text.strip():
        return None
    tokens = text.split()
    if not text[0].isspace() or tokens[0].endswith(":"):
        tokens = tokens[1:]  # a label in column 1 or one ending in ':'
    if not tokens:
        return None
    word = tokens[0].lower()
    return word.split(".", 1)[0] if size_suffixes else word


def instruction_bytes(listing, profile):
    """Bytes of the listing's instruction lines, in listing order; with
    `own_cpus`, only of lines assembled for the profile's processor."""
    out = bytearray()
    keep = False
    own_cpu = True
    for line in listing.splitlines():
        match = LISTING_LINE.match(line)
        if not match:
            continue
        field = line[match.end():match.end() + profile.bytes_field]
        if match.group(1) is not None:
            source = line[match.end() + profile.bytes_field:]
            directive = CPU_DIRECTIVE.match(source.split(";", 1)[0])
            if profile.own_cpus is not None and directive:
                own_cpu = bool(profile.own_cpus.match(directive.group(1)))
            keep = own_cpu and mnemonic(source, profile.size_suffixes) in profile.mnemonics
        if keep:
            out.extend(int(b, 16) for b in BYTE.findall(field))
    return bytes(out)


def assemble(asl, cpu, path, scratch):
    """asl's listing of one source for `cpu`, or None if it does not assemble."""
    key = hashlib.sha1(path.encode()).hexdigest()[:16]
    listing = os.path.join(scratch, key + ".lst")
    if os.path.exists(listing):
        os.remove(listing)  # a failed run must not leave an earlier listing to read
    command = [asl, "-cpu", cpu, "-L", "-q", "-olist", listing, "-o", os.path.join(scratch, key + ".p"),
               os.path.basename(path)]
    try:
        result = subprocess.run(command, cwd=os.path.dirname(path), capture_output=True,
                                timeout=ASSEMBLE_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0 or not os.path.exists(listing):
        return None
    return github_repos.read_text(listing)


STAR_COMMENT = re.compile(rb"^\*", re.MULTILINE)


def rewrite_star_comments(tree, suffixes):
    """Turn full-line `*` comments into `;` comments in the tree's sources."""
    for dirpath, _, files in os.walk(tree):
        for name in files:
            if name.lower().endswith(suffixes):
                path = os.path.join(dirpath, name)
                with open(path, "rb") as f:
                    text = f.read()
                rewritten = STAR_COMMENT.sub(b";", text)
                if rewritten != text:
                    with open(path, "wb") as f:
                        f.write(rewritten)


# An asm68k/Devpac local label: `@name` or `.name` not right after a name,
# register, number, `)` or `]` (which would make the `.` an operand-size
# suffix, as in `move.w` or `(a0).l`) or after a macro's `\`.
LOCAL_LABEL = re.compile(rb"(?<![\w$)\].@\\])[@.]([A-Za-z_]\w*)")
# A label in column 1 that is not local: it opens a new local-label scope.
SCOPE_LABEL = re.compile(rb"^[A-Za-z_]\w*")


def rename_local_labels(text):
    """`text` with each local label renamed `L<scope>_<name>`, the scope
    counting the column-1 labels before it, as asm68k scopes them."""
    lines = text.split(b"\n")
    scope = 0
    for i, line in enumerate(lines):
        if SCOPE_LABEL.match(line):
            scope += 1
        lines[i] = LOCAL_LABEL.sub(lambda m: b"L%d_%s" % (scope, m.group(1)), line)
    return b"\n".join(lines)


def rewrite_sources(tree, suffixes, rewrite):
    """Apply `rewrite` to the text of every source in the tree."""
    for dirpath, _, files in os.walk(tree):
        for name in files:
            if name.lower().endswith(suffixes):
                path = os.path.join(dirpath, name)
                with open(path, "rb") as f:
                    text = f.read()
                rewritten = rewrite(text)
                if rewritten != text:
                    with open(path, "wb") as f:
                        f.write(rewritten)


def repo_programs(tree, asl, profile, scratch):
    """(relative path, processor, code bytes) of every source that assembles."""
    if profile.star_comments:
        rewrite_star_comments(tree, profile.suffixes)
    if profile.local_labels:
        rewrite_sources(tree, profile.suffixes, rename_local_labels)
    for dirpath, _, files in os.walk(tree):
        for name in sorted(files):
            if not name.lower().endswith(profile.suffixes):
                continue
            path = os.path.join(dirpath, name)
            listing = assemble(asl, profile.cpu, path, scratch)
            if listing is None:
                continue
            code = instruction_bytes(listing, profile)
            if code:
                yield os.path.relpath(path, tree), profile.cpu, code


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--asl", required=True, help="path to the asl executable")
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("repos", help="TSV: owner/name, SPDX license, branch")
    parser.add_argument("work", help="download and scratch directory")
    parser.add_argument("out", help="output directory (one .bin per repository); its name is the corpus class")
    parser.add_argument("provenance", help="markdown file to append provenance rows to")
    args = parser.parse_args()
    asl = os.path.abspath(args.asl)
    profile = PROFILES[args.profile]
    scratch = os.path.abspath(os.path.join(args.work, "lst"))
    os.makedirs(scratch, exist_ok=True)

    def describe(count, _processors):
        comments = "; full-line '*' comments rewritten to ';'" if profile.star_comments else ""
        return (f"asl 1.42 (-cpu {profile.cpu}) build of {count} source(s){comments}; bytes of instruction lines "
                "from the listing, data directives dropped")

    github_repos.harvest(args.repos, args.work, args.out, args.provenance,
                         lambda tree: repo_programs(tree, asl, profile, scratch), describe)


if __name__ == "__main__":
    main()
