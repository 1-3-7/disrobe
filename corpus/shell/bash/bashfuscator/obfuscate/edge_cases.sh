#!/usr/bin/env bash
 ${@,,}   ${*^^} ''\pr${*}i\ntf  %s "$(      F8DNZi='SET -eEUO PIPEFAIL
ifs=$'"'"'\N\T'"'"'

name='"'"'HELLO WORLD'"'"'
defaulted="${unset_var:-DEFAULT-VALUE}"
assigned="${maybe_unset:=ALT-DEFAULT}"
error_if_unset="${name:?MUST BE SET}"
alternate="${name:+ALTERNATE-WHEN-SET}"
substring="${name:0:5}"
substring_neg="${name: -5}"
length="${#name}"

path_like='"'"'/USR/LOCAL/BIN/EXAMPLE'"'"'
basename="${path_like##*/}"
dirname="${path_like%/*}"
extension="${path_like##*.}"
stem="${path_like%.*}"

replace_first="${name/HELLO/HI}"
replace_all="${name//L/l}"
replace_prefix="${name/#HELLO/hello}"
replace_suffix="${name/%WORLD/world}"

upper_first="${name^}"
upper_all="${name^^}"
lower_first="${name,}"
lower_all="${name,,}"
swapcase="${name~~}"

quoted_list=( "${name}" "${basename}" "${dirname}" )
indirect_name='"'"'name'"'"'
indirect_value="${!indirect_name}"

DECLARE -a assoc
assoc[ALPHA]=1
assoc[BETA]=2
assoc[GAMMA]=3
all_keys="${!assoc[@]}"
all_vals="${assoc[@]}"

count=10
sum=$((count + 5))
prod=$((count * 7))
shifted=$((1 << 4))
masked=$((0Xff & 0X0f))
ternary=$((count > 5 ? 1 : 0))
LET "inc = count + 1"
((postfix = count + 1))
precise="$(AWK '"'"'begin { PRINTF "%.3F", 22 / 7 }'"'"')"

indexed=( ONE TWO THREE FOUR FIVE )
indexed+=( SIX SEVEN )
slice=( "${indexed[@]:2:3}" )
length_arr="${#indexed[@]}"
last="${indexed[-1]}"
indices=( "${!indexed[@]}" )

UNSET indexed[1]
DECLARE -A nums
FOR I IN {0..9}; DO
    nums[$I]=$((I * I))
DONE

DECLARE -a config
config[HOST]=LOCALHOST
config[PORT]=8080
config[TIMEOUT]=30
FOR KEY IN "${!config[@]}"; DO
    ECHO "$KEY=${config[$KEY]}" >/DEV/NULL
DONE

current_date="$(DATE +%y-%M-%D)"
kernel_release="$(UNAME -R)"
nested="$(ECHO "$(ECHO "$(ECHO NESTED)")")"
backtick_legacy=`DATE +%y`
processes="$(PS -EF 2>/DEV/NULL | WC -L)"

DIFF <(ECHO -E "A\NB\NC") <(ECHO -E "A\Nb\NC") >/DEV/NULL 2>&1 || TRUE
CAT <(SEQ 1 5) <(SEQ 6 10) >/DEV/NULL
EXEC 3< <(SEQ 1 100)
READ -R first_line <&3
EXEC 3<&-

heredoc_plain=$(CAT <<'"'"'eof'"'"'
NO $INTERPOLATION
LITERAL BACKTICKS `CMD`
MULTIPLE LINES
eof
)

heredoc_interp=$(CAT <<eof
GREETING FROM $name
HOST IS ${config[HOST]}
eof
)

heredoc_tab=$(CAT <<-indented
	INDENTED HEREDOC
	LEADING TABS STRIPPED
indented
)

here_string=$(TR '"'"'A-Z'"'"' '"'"'a-z'"'"' <<<"$name")

EXEC 4>/DEV/NULL
ECHO '"'"'DISCARDED'"'"' >&4

logfile='"'"'/DEV/NULL'"'"'
{
    ECHO '"'"'GROUP-1'"'"'
    ECHO '"'"'GROUP-2'"'"'
} >"$logfile"

all_output=$( { ECHO '"'"'STDOUT'"'"'; ECHO '"'"'STDERR'"'"' >&2; } 2>&1 )

CAT /NONEXISTENT 2>/DEV/NULL || TRUE

err_only="$(MKTEMP)" && TRAP "RM -F '"'"'$err_only'"'"'" exit
ECHO '"'"'OOPS'"'"' 2>"$err_only" >/DEV/NULL

ON_EXIT() {
    LOCAL CODE=$?
    RETURN $CODE
}
ON_ERR() {
    LOCAL CODE=$?
    LOCAL LINE=$1
    ECHO "TRAP: err CODE=$CODE LINE=$LINE" >&2
    RETURN $CODE
}
ON_INT() {
    ECHO '"'"'CAUGHT sigint'"'"' >&2
    EXIT 130
}
TRAP '"'"'ON_EXIT'"'"' exit
TRAP '"'"'ON_ERR $lineno'"'"' err
TRAP '"'"'ON_INT'"'"' int term

brace_seq=( {1..10} )
brace_step=( {0..20..2} )
brace_letters=( {A..F} )
brace_pair=( FILE{1..3}.{LOG,TXT} )
brace_padded=( {01..05} )
brace_reverse=( {10..1} )

SHOPT -S NULLGLOB
SHOPT -S EXTGLOB
SHOPT -S GLOBSTAR
SHOPT -S NOCASEGLOB

ps_files=( **/*.PS1 )
null_glob_result=( /NO-SUCH-DIR/*.X )

extglob_not_log=( !(.LOG) )
extglob_at_least_one=( +(A|B|C) )
extglob_exactly_one=( @(YES|NO) )
extglob_never=( !(*) )

SHOPT -U NOCASEGLOB

STR_A='"'"'FOO'"'"'
STR_B='"'"'BAR'"'"'
IF [[ "$STR_A" == "$STR_B" ]]; THEN :; FI
IF [[ "$STR_A" =~ ^F[A-Z]+$ ]]; THEN
    rx_group_0="${bash_rematch[0]}"
FI
IF [[ -E /ETC/PASSWD && -R /ETC/PASSWD ]]; THEN :; FI
IF [[ "$STR_A" < "$STR_B" ]]; THEN :; FI
IF [ "$STR_A" = "$STR_B" ]; THEN :; FI
TEST -D /TMP && TEST -W /TMP

FILE_EXISTS() {
    [[ -F "$1" ]]
}
FILE_EXECUTABLE() {
    [[ -X "$1" ]]
}
FILE_NEWER_THAN() {
    [[ "$1" -NT "$2" ]]
}
FILES_SAME_INODE() {
    [[ "$1" -EF "$2" ]]
}
NOT_EMPTY() {
    [[ -N "$1" ]]
}
IS_EMPTY() {
    [[ -Z "$1" ]]
}

CLASSIFY() {
    LOCAL ARG="$1"
    CASE "$ARG" IN
        *.TAR.GZ|*.TGZ)
            ECHO '"'"'GZIP-TAR'"'"' ;;
        *.TAR.XZ|*.TXZ)
            ECHO '"'"'XZ-TAR'"'"' ;;
        *.TAR.BZ2|*.TBZ)
            ECHO '"'"'BZIP2-TAR'"'"' ;;
        *.ZIP)
            ECHO '"'"'ZIP'"'"' ;;
        [0-9]*)
            ECHO '"'"'NUMERIC-PREFIX'"'"' ;;
        +([A-Z])-+([A-Z]))
            ECHO '"'"'TWO-WORDS'"'"' ;;
        ?(_|.)*)
            ECHO '"'"'MAYBE-HIDDEN'"'"' ;;
        *)
            ECHO '"'"'UNKNOWN'"'"' ;;
    ESAC
}

FOR I IN 1 2 3 4 5; DO
    ECHO "$I" >/DEV/NULL
DONE
FOR ((I = 0; I < 10; I++)); DO
    ECHO "$I" >/DEV/NULL
DONE
FOR F IN ./*.TMP; DO
    [[ -E "$F" ]] || CONTINUE
    ECHO "$F" >/DEV/NULL
DONE

N=0
WHILE (( N < 5 )); DO
    N=$((N + 1))
DONE

M=10
UNTIL (( M <= 0 )); DO
    M=$((M - 1))
DONE

SELECT CHOICE IN '"'"'FIRST'"'"' '"'"'SECOND'"'"' '"'"'THIRD'"'"' '"'"'QUIT'"'"'; DO
    CASE "$CHOICE" IN
        FIRST|SECOND|THIRD)
            ECHO "PICKED $CHOICE" >/DEV/NULL
            BREAK ;;
        QUIT)
            BREAK ;;
        *)
            ECHO '"'"'INVALID'"'"' >/DEV/NULL ;;
    ESAC
DONE </DEV/NULL

DECLARE -I int_var=42
DECLARE -R ro_var='"'"'READ-ONLY'"'"'
DECLARE -A idx_arr=( A B C )
DECLARE -a assoc_arr=( [X]=1 [Y]=2 )
DECLARE -L lower_var
lower_var='"'"'hello'"'"'
DECLARE -U upper_var
upper_var='"'"'HELLO'"'"'
DECLARE -X exported='"'"'VISIBLE-TO-CHILDREN'"'"'
DECLARE -N ref_to_name=name

READONLY const_pi=3.14159
TYPESET -I counter=0

SCOPED_FUNCTION() {
    LOCAL local_var='"'"'INSIDE'"'"'
    LOCAL -I local_int=99
    LOCAL -A local_arr=( 1 2 3 )
    LOCAL -R local_ro='"'"'CANNOT-CHANGE'"'"'
    ECHO "$local_var $local_int ${local_arr[*]} $local_ro" >/DEV/NULL
}

IF TYPE -T ECHO | GREP -Q BUILTIN; THEN :; FI
HASH -R
COMMAND -V LS >/DEV/NULL
ENABLE -N ECHO 2>/DEV/NULL || TRUE
ENABLE ECHO 2>/DEV/NULL || TRUE

BUILTIN PRINTF '"'"'%S\N'"'"' '"'"'VIA-BUILTIN'"'"' >/DEV/NULL
\PRINTF '"'"'%S\N'"'"' '"'"'BYPASSING-ALIAS'"'"' >/DEV/NULL
EXEC ENV -I BASH -C '"'"'ECHO CLEAN-ENV'"'"' 2>/DEV/NULL >/DEV/NULL || TRUE

KILL -L >/DEV/NULL
LIST_SIGNALS() {
    TRAP -L | TR -S '"'"' '"'"'
}
SIGUSR1_HANDLER() {
    ECHO '"'"'USR1 RECEIVED'"'"' >&2
}
SIGUSR2_HANDLER() {
    ECHO '"'"'USR2 RECEIVED'"'"' >&2
}
TRAP '"'"'SIGUSR1_HANDLER'"'"' usr1
TRAP '"'"'SIGUSR2_HANDLER'"'"' usr2
TRAP '"'"''"'"' pipe
TRAP - hup

PARSE_ARGS() {
    LOCAL optind=1
    LOCAL OPT VERBOSE=0 INPUT='"'"''"'"' OUTPUT='"'"'/DEV/STDOUT'"'"'
    WHILE GETOPTS '"'"':VHI:O:'"'"' OPT; DO
        CASE "$OPT" IN
            V) VERBOSE=1 ;;
            H) ECHO '"'"'USAGE: PARSE_ARGS -V -I input -O output'"'"'; RETURN 0 ;;
            I) INPUT="$optarg" ;;
            O) OUTPUT="$optarg" ;;
            :) ECHO "MISSING ARG FOR -$optarg" >&2; RETURN 2 ;;
            \?) ECHO "UNKNOWN -$optarg" >&2; RETURN 2 ;;
        ESAC
    DONE
    SHIFT $((optind - 1))
    PRINTF '"'"'VERBOSE=%D INPUT=%S OUTPUT=%S REST=%S\N'"'"' "$VERBOSE" "$INPUT" "$OUTPUT" "$*"
}

GREET() {
    LOCAL WHO="${1:-WORLD}"
    PRINTF '"'"'HELLO %S\N'"'"' "$WHO"
}

SQUARE() {
    LOCAL N="$1"
    ECHO $((N * N))
}

DIV() {
    LOCAL A="$1" B="$2"
    IF (( B == 0 )); THEN
        ECHO '"'"'DIVIDE BY ZERO'"'"' >&2
        RETURN 1
    FI
    ECHO $((A / B))
}

RETURNS_NAMED() {
    DECLARE -N OUT_REF="$1"
    SHIFT
    OUT_REF="$*"
}

RETURNS_ARRAY() {
    DECLARE -N ARR_REF="$1"
    SHIFT
    ARR_REF=( "$@" )
}

MAPFILE -T lines < <(SEQ 1 5)
line_count="${#lines[@]}"

READARRAY -T words < <(PRINTF '"'"'%S\N'"'"' APPLE BANANA CHERRY DATE)

COPROC hello_co { WHILE READ -R LINE; DO ECHO "GOT: $LINE"; DONE; }
ECHO '"'"'PING'"'"' >&"${hello_co[1]}"
READ -T 1 -R reply <&"${hello_co[0]}" || TRUE
EXEC {hello_co[1]}>&-
WAIT "$hello_co_pid" 2>/DEV/NULL || TRUE

var='"'"'HELLO WORLD'"'"'
quoted_repr="${var@q}"
escaped_prompt="${var@p}"
assign_repr="${var@a}"
typed_repr="${var@A}"

OUTER() {
    LOCAL outer_var='"'"'OUTER-VALUE'"'"'
    INNER
}
INNER() {
    LOCAL inner_var='"'"'INNER-VALUE'"'"'
    ECHO "$outer_var $inner_var" >/DEV/NULL
}

result_subshell=$( CD /TMP 2>/DEV/NULL && PWD )
result_group=$( { CD /TMP 2>/DEV/NULL && PWD; } )

DETECT_PIPEFAIL() {
    SET -O PIPEFAIL
    IF FALSE | TRUE; THEN
        ECHO '"'"'NO PIPEFAIL'"'"' >/DEV/NULL
    ELSE
        ECHO '"'"'PIPEFAIL ACTIVE'"'"' >/DEV/NULL
    FI
    SET +O PIPEFAIL
}

LIST_CHILDREN() {
    LOCAL PARENT="${1:-$$}"
    PGREP -p "$PARENT" 2>/DEV/NULL || TRUE
}
WAIT_ALL() {
    WHILE (( $# > 0 )); DO
        WAIT "$1" || TRUE
        SHIFT
    DONE
}

JOIN_WORDS() {
    LOCAL ifs="$1"
    SHIFT
    ECHO "$*"
}
SPLIT_WORDS() {
    LOCAL ifs=$'"'"' \T\N'"'"'
    LOCAL INPUT="$1"
    READ -RA PARTS <<<"$INPUT"
    PRINTF '"'"'%S\N'"'"' "${PARTS[@]}"
}

LIST_ENV_KEYS() {
    COMPGEN -E
}
UNSET_SOME() {
    UNSET not_set_var
    EXPORT -N exported 2>/DEV/NULL || TRUE
}

SECONDS_SINCE_EPOCH() {
    DATE +%S
}
DAYS_UNTIL() {
    LOCAL TARGET="$1"
    LOCAL NOW THEN
    NOW=$(DATE +%S)
    THEN=$(DATE -D "$TARGET" +%S 2>/DEV/NULL || ECHO "$NOW")
    ECHO $(( (THEN - NOW) / 86400 ))
}

TO_DECIMAL() {
    LOCAL RAW="$1"
    CASE "$RAW" IN
        0X*|0x*) PRINTF '"'"'%D\N'"'"' "$RAW" ;;
        0[0-7]*) PRINTF '"'"'%D\N'"'"' "$RAW" ;;
        *) PRINTF '"'"'%D\N'"'"' "$RAW" ;;
    ESAC
}

EMIT_RECORD() {
    LOCAL ID="$1" NAME="$2"
    PRINTF '"'"'{"ID":%D,"NAME":%S}\N'"'"' "$ID" "${NAME@q}"
}

PING_COPROC() {
    COPROC ping { SLEEP 0.05; ECHO PONG; }
    IF READ -T 1 -R RESP <&"${ping[0]}"; THEN
        ECHO "$RESP" >/DEV/NULL
    FI
    WAIT "$ping_pid" 2>/DEV/NULL || TRUE
}

ON_RETURN() {
    ECHO "LEAVING ${funcname[1]}" >/DEV/NULL
}
RETURN_TRAP_DEMO() {
    TRAP '"'"'ON_RETURN'"'"' return
    LOCAL _X=1
    TRAP - return
}

SELF_TEST() {
    GREET '"'"'TESTER'"'"' >/DEV/NULL
    SQUARE 7 >/DEV/NULL
    DIV 10 2 >/DEV/NULL
    CLASSIFY HELLO.ZIP >/DEV/NULL
    CLASSIFY ARCHIVE.TAR.GZ >/DEV/NULL
    PARSE_ARGS -V -I IN -O OUT REST1 REST2 >/DEV/NULL
    JOIN_WORDS '"'"','"'"' A B C >/DEV/NULL
    PING_COPROC
    RETURN_TRAP_DEMO
}

MAIN() {
    SELF_TEST
    ECHO '"'"'HELLO WORLD'"'"'
}

IF [[ "${bash_source[0]}" == "$0" ]]; THEN
    MAIN "$@"
FI

FUNCTION LEGACY_KEYWORD_FORM {
    ECHO '"'"'FUNCTION-KEYWORD FORM'"'"'
}
FUNCTION MODERN_PAREN_FORM() {
    ECHO '"'"'FUNCTION-KEYWORD + PAREN FORM'"'"'
}
SHORT_FORM() {
    ECHO '"'"'SHORT FORM'"'"'
}

FETCH_URL() {
    LOCAL URL="$1"
    IF COMMAND -V CURL >/DEV/NULL; THEN
        CURL -FSsl --MAX-TIME 10 "$URL"
    ELIF COMMAND -V WGET >/DEV/NULL; THEN
        WGET -Qo- --TIMEOUT=10 "$URL"
    ELIF (( bash_versinfo[0] >= 4 )); THEN
        LOCAL HOST PATH
        HOST="${URL#*://}"
        HOST="${HOST%%/*}"
        PATH="/${URL#*://*/}"
        EXEC 3<>"/DEV/TCP/$HOST/80"
        PRINTF '"'"'get %S http/1.0\R\NhOST: %S\R\N\R\N'"'"' "$PATH" "$HOST" >&3
        CAT <&3
        EXEC 3<&-
    ELSE
        RETURN 1
    FI
}

DESCRIPTOR_DANCE() {
    EXEC 5>/DEV/NULL
    EXEC 6>&1
    EXEC 1>&5
    ECHO '"'"'THIS GOES TO FD 5 (NOW STDOUT)'"'"' >/DEV/NULL
    EXEC 1>&6
    EXEC 5>&-
    EXEC 6>&-
}

ALL_LOWERCASE() {
    [[ "$1" =~ ^[A-Z]+$ ]]
}
HEX_DIGITS_ONLY() {
    [[ "$1" =~ ^[0-9A-Fa-f]+$ ]]
}
ENDS_WITH() {
    [[ "$1" == *"$2" ]]
}
STARTS_WITH() {
    [[ "$1" == "$2"* ]]
}
CONTAINS() {
    [[ "$1" == *"$2"* ]]
}

PAD_ZERO() {
    PRINTF '"'"'%05D\N'"'"' "$1"
}
HEX_FORMAT() {
    PRINTF '"'"'0X%08x\N'"'"' "$1"
}
BINARY_STR() {
    LOCAL N="$1"
    LOCAL OUT='"'"''"'"'
    WHILE (( N > 0 )); DO
        OUT="$((N % 2))$OUT"
        N=$((N / 2))
    DONE
    [[ -Z "$OUT" ]] && OUT='"'"'0'"'"'
    ECHO "$OUT"
}

SLICE_POP_BACK() {
    LOCAL -N ARR_REF="$1"
    LOCAL LAST="${ARR_REF[-1]}"
    ARR_REF=( "${ARR_REF[@]:0:${#ARR_REF[@]}-1}" )
    ECHO "$LAST"
}
SLICE_POP_FRONT() {
    LOCAL -N ARR_REF="$1"
    LOCAL FIRST="${ARR_REF[0]}"
    ARR_REF=( "${ARR_REF[@]:1}" )
    ECHO "$FIRST"
}
ARR_REVERSE() {
    LOCAL -N ARR_REF="$1"
    LOCAL LEN="${#ARR_REF[@]}" TMP
    LOCAL -I I J
    FOR (( I = 0, J = LEN - 1; I < J; I++, J-- )); DO
        TMP="${ARR_REF[$I]}"
        ARR_REF[$I]="${ARR_REF[$J]}"
        ARR_REF[$J]="$TMP"
    DONE
}
ARR_CONTAINS() {
    LOCAL NEEDLE="$1"
    SHIFT
    LOCAL ITEM
    FOR ITEM IN "$@"; DO
        [[ "$ITEM" == "$NEEDLE" ]] && RETURN 0
    DONE
    RETURN 1
}

REQUIRE_BASH() {
    LOCAL NEEDED_MAJOR="$1"
    IF (( bash_versinfo[0] < NEEDED_MAJOR )); THEN
        ECHO "NEEDS BASH $NEEDED_MAJOR+, HAVE ${bash_version}" >&2
        RETURN 1
    FI
}

ACQUIRE_LOCK() {
    LOCAL LOCKFILE="$1"
    LOCAL TIMEOUT="${2:-30}"
    LOCAL WAITED=0
    WHILE ! ( SET -c; ECHO "$$" >"$LOCKFILE" ) 2>/DEV/NULL; DO
        SLEEP 1
        WAITED=$((WAITED + 1))
        IF (( WAITED >= TIMEOUT )); THEN
            RETURN 1
        FI
    DONE
    TRAP "RM -F '"'"'$LOCKFILE'"'"'" exit
}

PROCESS_LINES() {
    LOCAL INPUT="$1"
    WHILE ifs= READ -R LINE; DO
        PRINTF '"'"'GOT: %S\N'"'"' "$LINE"
    DONE <"$INPUT"
}

SHOPT -S LASTPIPE 2>/DEV/NULL || TRUE
SUM_LINES_PIPE() {
    LOCAL TOTAL=0 LINE
    SEQ 1 10 | WHILE READ -R LINE; DO
        TOTAL=$((TOTAL + LINE))
    DONE
    ECHO "$TOTAL"
}

WALK_PGRP() {
    LOCAL PID="${1:-$$}"
    LOCAL DEPTH="${2:-0}"
    LOCAL INDENT='"'"''"'"'
    LOCAL _I
    FOR ((_I = 0; _I < DEPTH; _I++)); DO
        INDENT+='"'"'  '"'"'
    DONE
    ECHO "${INDENT}${PID}"
    LOCAL CHILD
    FOR CHILD IN $(PGREP -p "$PID" 2>/DEV/NULL); DO
        WALK_PGRP "$CHILD" $((DEPTH + 1))
    DONE
}

DECLARE -a set_store
SET_ADD() {
    set_store["$1"]=1
}
SET_HAS() {
    [[ -N "${set_store[$1]+_}" ]]
}
SET_REMOVE() {
    UNSET '"'"'set_store['"'"'$1'"'"']'"'"'
}
SET_SIZE() {
    ECHO "${#set_store[@]}"
}
SET_ITER() {
    LOCAL K
    FOR K IN "${!set_store[@]}"; DO
        PRINTF '"'"'%S\N'"'"' "$K"
    DONE
}

DECLARE -a memo_fib
FIB_MEMO() {
    LOCAL N="$1"
    IF (( N < 2 )); THEN
        ECHO "$N"
        RETURN 0
    FI
    IF [[ -N "${memo_fib[$N]+_}" ]]; THEN
        ECHO "${memo_fib[$N]}"
        RETURN 0
    FI
    LOCAL A B SUM
    A="$(FIB_MEMO $((N - 1)))"
    B="$(FIB_MEMO $((N - 2)))"
    SUM=$((A + B))
    memo_fib["$N"]="$SUM"
    ECHO "$SUM"
}

FIFO_DEMO() {
    LOCAL FIFO
    FIFO="$(MKTEMP -U)"
    MKFIFO "$FIFO"
    ( WHILE READ -R LN; DO
          [[ -Z "$LN" ]] && BREAK
          ECHO "CONSUMER: $LN"
      DONE <"$FIFO" ) &
    LOCAL CPID=$!
    {
        ECHO '"'"'ONE'"'"'
        ECHO '"'"'TWO'"'"'
        ECHO '"'"''"'"'
    } >"$FIFO"
    WAIT "$CPID" 2>/DEV/NULL || TRUE
    RM -F "$FIFO"
}

DECLARE -a pERSON
pERSON_INIT() {
    pERSON[NAME]="$1"
    pERSON[AGE]="$2"
}
pERSON_GREET() {
    PRINTF '"'"'i AM %S, %S YEARS OLD\N'"'"' "${pERSON[NAME]}" "${pERSON[AGE]}"
}
pERSON_BIRTHDAY() {
    pERSON[AGE]=$(( ${pERSON[AGE]} + 1 ))
}

CHAIN_TRAP() {
    LOCAL CUR NEXT
    CUR="$(TRAP -P exit | SED -N "S/^TRAP -- '"'"'\(.*\)'"'"' exit\$/\1/P")"
    NEXT="ECHO '"'"'EXTRA EXIT HOOK'"'"'; ${CUR:-TRUE}"
    TRAP "$NEXT" exit
}


' ${*//Ho\}Eoqj}   ${*^^} ;   "${@,,}"   "${@^^}"  pr${@~~}i\ntf  %s   "${F8DNZi~~}" ${*,}  "${@,}"   ${*/|ZknJD/rokfi}   "${@#5zBSL\[<}"     )"  ${@~~}  "${@//s\!RSBWl|}"   |  ${@^} ${@,,}   $BASH ${*/Md4\)3KZU/ZGDGMQ9} 