#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

NAME='hello world'
DEFAULTED="${UNSET_VAR:-default-value}"
ASSIGNED="${MAYBE_UNSET:=alt-default}"
ERROR_IF_UNSET="${NAME:?must be set}"
ALTERNATE="${NAME:+alternate-when-set}"
SUBSTRING="${NAME:0:5}"
SUBSTRING_NEG="${NAME: -5}"
LENGTH="${#NAME}"

PATH_LIKE='/usr/local/bin/example'
BASENAME="${PATH_LIKE##*/}"
DIRNAME="${PATH_LIKE%/*}"
EXTENSION="${PATH_LIKE##*.}"
STEM="${PATH_LIKE%.*}"

REPLACE_FIRST="${NAME/hello/hi}"
REPLACE_ALL="${NAME//l/L}"
REPLACE_PREFIX="${NAME/#hello/HELLO}"
REPLACE_SUFFIX="${NAME/%world/WORLD}"

UPPER_FIRST="${NAME^}"
UPPER_ALL="${NAME^^}"
LOWER_FIRST="${NAME,}"
LOWER_ALL="${NAME,,}"
SWAPCASE="${NAME~~}"

QUOTED_LIST=( "${NAME}" "${BASENAME}" "${DIRNAME}" )
INDIRECT_NAME='NAME'
INDIRECT_VALUE="${!INDIRECT_NAME}"

declare -A ASSOC
ASSOC[alpha]=1
ASSOC[beta]=2
ASSOC[gamma]=3
ALL_KEYS="${!ASSOC[@]}"
ALL_VALS="${ASSOC[@]}"

COUNT=10
SUM=$((COUNT + 5))
PROD=$((COUNT * 7))
SHIFTED=$((1 << 4))
MASKED=$((0xFF & 0x0F))
TERNARY=$((COUNT > 5 ? 1 : 0))
let "INC = COUNT + 1"
((POSTFIX = COUNT + 1))
PRECISE="$(awk 'BEGIN { printf "%.3f", 22 / 7 }')"

INDEXED=( one two three four five )
INDEXED+=( six seven )
SLICE=( "${INDEXED[@]:2:3}" )
LENGTH_ARR="${#INDEXED[@]}"
LAST="${INDEXED[-1]}"
INDICES=( "${!INDEXED[@]}" )

unset INDEXED[1]
declare -a NUMS
for i in {0..9}; do
    NUMS[$i]=$((i * i))
done

declare -A CONFIG
CONFIG[host]=localhost
CONFIG[port]=8080
CONFIG[timeout]=30
for key in "${!CONFIG[@]}"; do
    echo "$key=${CONFIG[$key]}" >/dev/null
done

CURRENT_DATE="$(date +%Y-%m-%d)"
KERNEL_RELEASE="$(uname -r)"
NESTED="$(echo "$(echo "$(echo nested)")")"
BACKTICK_LEGACY=`date +%Y`
PROCESSES="$(ps -ef 2>/dev/null | wc -l)"

diff <(echo -e "a\nb\nc") <(echo -e "a\nB\nc") >/dev/null 2>&1 || true
cat <(seq 1 5) <(seq 6 10) >/dev/null
exec 3< <(seq 1 100)
read -r FIRST_LINE <&3
exec 3<&-

HEREDOC_PLAIN=$(cat <<'EOF'
no $interpolation
literal backticks `cmd`
multiple lines
EOF
)

HEREDOC_INTERP=$(cat <<EOF
greeting from $NAME
host is ${CONFIG[host]}
EOF
)

HEREDOC_TAB=$(cat <<-INDENTED
	indented heredoc
	leading tabs stripped
INDENTED
)

HERE_STRING=$(tr 'a-z' 'A-Z' <<<"$NAME")

exec 4>/dev/null
echo 'discarded' >&4

LOGFILE='/dev/null'
{
    echo 'group-1'
    echo 'group-2'
} >"$LOGFILE"

ALL_OUTPUT=$( { echo 'stdout'; echo 'stderr' >&2; } 2>&1 )

cat /nonexistent 2>/dev/null || true

ERR_ONLY="$(mktemp)" && trap "rm -f '$ERR_ONLY'" EXIT
echo 'oops' 2>"$ERR_ONLY" >/dev/null

on_exit() {
    local code=$?
    return $code
}
on_err() {
    local code=$?
    local line=$1
    echo "trap: ERR code=$code line=$line" >&2
    return $code
}
on_int() {
    echo 'caught SIGINT' >&2
    exit 130
}
trap 'on_exit' EXIT
trap 'on_err $LINENO' ERR
trap 'on_int' INT TERM

BRACE_SEQ=( {1..10} )
BRACE_STEP=( {0..20..2} )
BRACE_LETTERS=( {a..f} )
BRACE_PAIR=( file{1..3}.{log,txt} )
BRACE_PADDED=( {01..05} )
BRACE_REVERSE=( {10..1} )

shopt -s nullglob
shopt -s extglob
shopt -s globstar
shopt -s nocaseglob

PS_FILES=( **/*.ps1 )
NULL_GLOB_RESULT=( /no-such-dir/*.x )

EXTGLOB_NOT_LOG=( !(.log) )
EXTGLOB_AT_LEAST_ONE=( +(a|b|c) )
EXTGLOB_EXACTLY_ONE=( @(yes|no) )
EXTGLOB_NEVER=( !(*) )

shopt -u nocaseglob

str_a='foo'
str_b='bar'
if [[ "$str_a" == "$str_b" ]]; then :; fi
if [[ "$str_a" =~ ^f[a-z]+$ ]]; then
    RX_GROUP_0="${BASH_REMATCH[0]}"
fi
if [[ -e /etc/passwd && -r /etc/passwd ]]; then :; fi
if [[ "$str_a" < "$str_b" ]]; then :; fi
if [ "$str_a" = "$str_b" ]; then :; fi
test -d /tmp && test -w /tmp

file_exists() {
    [[ -f "$1" ]]
}
file_executable() {
    [[ -x "$1" ]]
}
file_newer_than() {
    [[ "$1" -nt "$2" ]]
}
files_same_inode() {
    [[ "$1" -ef "$2" ]]
}
not_empty() {
    [[ -n "$1" ]]
}
is_empty() {
    [[ -z "$1" ]]
}

classify() {
    local arg="$1"
    case "$arg" in
        *.tar.gz|*.tgz)
            echo 'gzip-tar' ;;
        *.tar.xz|*.txz)
            echo 'xz-tar' ;;
        *.tar.bz2|*.tbz)
            echo 'bzip2-tar' ;;
        *.zip)
            echo 'zip' ;;
        [0-9]*)
            echo 'numeric-prefix' ;;
        +([a-z])-+([a-z]))
            echo 'two-words' ;;
        ?(_|.)*)
            echo 'maybe-hidden' ;;
        *)
            echo 'unknown' ;;
    esac
}

for i in 1 2 3 4 5; do
    echo "$i" >/dev/null
done
for ((i = 0; i < 10; i++)); do
    echo "$i" >/dev/null
done
for f in ./*.tmp; do
    [[ -e "$f" ]] || continue
    echo "$f" >/dev/null
done

n=0
while (( n < 5 )); do
    n=$((n + 1))
done

m=10
until (( m <= 0 )); do
    m=$((m - 1))
done

select choice in 'first' 'second' 'third' 'quit'; do
    case "$choice" in
        first|second|third)
            echo "picked $choice" >/dev/null
            break ;;
        quit)
            break ;;
        *)
            echo 'invalid' >/dev/null ;;
    esac
done </dev/null

declare -i INT_VAR=42
declare -r RO_VAR='read-only'
declare -a IDX_ARR=( a b c )
declare -A ASSOC_ARR=( [x]=1 [y]=2 )
declare -l LOWER_VAR
LOWER_VAR='HELLO'
declare -u UPPER_VAR
UPPER_VAR='hello'
declare -x EXPORTED='visible-to-children'
declare -n REF_TO_NAME=NAME

readonly CONST_PI=3.14159
typeset -i COUNTER=0

scoped_function() {
    local LOCAL_VAR='inside'
    local -i LOCAL_INT=99
    local -a LOCAL_ARR=( 1 2 3 )
    local -r LOCAL_RO='cannot-change'
    echo "$LOCAL_VAR $LOCAL_INT ${LOCAL_ARR[*]} $LOCAL_RO" >/dev/null
}

if type -t echo | grep -q builtin; then :; fi
hash -r
command -v ls >/dev/null
enable -n echo 2>/dev/null || true
enable echo 2>/dev/null || true

builtin printf '%s\n' 'via-builtin' >/dev/null
\printf '%s\n' 'bypassing-alias' >/dev/null
exec env -i bash -c 'echo clean-env' 2>/dev/null >/dev/null || true

kill -l >/dev/null
list_signals() {
    trap -l | tr -s ' '
}
sigusr1_handler() {
    echo 'usr1 received' >&2
}
sigusr2_handler() {
    echo 'usr2 received' >&2
}
trap 'sigusr1_handler' USR1
trap 'sigusr2_handler' USR2
trap '' PIPE
trap - HUP

parse_args() {
    local OPTIND=1
    local opt verbose=0 input='' output='/dev/stdout'
    while getopts ':vhi:o:' opt; do
        case "$opt" in
            v) verbose=1 ;;
            h) echo 'usage: parse_args -v -i INPUT -o OUTPUT'; return 0 ;;
            i) input="$OPTARG" ;;
            o) output="$OPTARG" ;;
            :) echo "missing arg for -$OPTARG" >&2; return 2 ;;
            \?) echo "unknown -$OPTARG" >&2; return 2 ;;
        esac
    done
    shift $((OPTIND - 1))
    printf 'verbose=%d input=%s output=%s rest=%s\n' "$verbose" "$input" "$output" "$*"
}

greet() {
    local who="${1:-world}"
    printf 'hello %s\n' "$who"
}

square() {
    local n="$1"
    echo $((n * n))
}

div() {
    local a="$1" b="$2"
    if (( b == 0 )); then
        echo 'divide by zero' >&2
        return 1
    fi
    echo $((a / b))
}

returns_named() {
    declare -n out_ref="$1"
    shift
    out_ref="$*"
}

returns_array() {
    declare -n arr_ref="$1"
    shift
    arr_ref=( "$@" )
}

mapfile -t LINES < <(seq 1 5)
LINE_COUNT="${#LINES[@]}"

readarray -t WORDS < <(printf '%s\n' apple banana cherry date)

coproc HELLO_CO { while read -r line; do echo "got: $line"; done; }
echo 'ping' >&"${HELLO_CO[1]}"
read -t 1 -r REPLY <&"${HELLO_CO[0]}" || true
exec {HELLO_CO[1]}>&-
wait "$HELLO_CO_PID" 2>/dev/null || true

VAR='hello world'
QUOTED_REPR="${VAR@Q}"
ESCAPED_PROMPT="${VAR@P}"
ASSIGN_REPR="${VAR@A}"
TYPED_REPR="${VAR@a}"

outer() {
    local OUTER_VAR='outer-value'
    inner
}
inner() {
    local INNER_VAR='inner-value'
    echo "$OUTER_VAR $INNER_VAR" >/dev/null
}

RESULT_SUBSHELL=$( cd /tmp 2>/dev/null && pwd )
RESULT_GROUP=$( { cd /tmp 2>/dev/null && pwd; } )

detect_pipefail() {
    set -o pipefail
    if false | true; then
        echo 'no pipefail' >/dev/null
    else
        echo 'pipefail active' >/dev/null
    fi
    set +o pipefail
}

list_children() {
    local parent="${1:-$$}"
    pgrep -P "$parent" 2>/dev/null || true
}
wait_all() {
    while (( $# > 0 )); do
        wait "$1" || true
        shift
    done
}

join_words() {
    local IFS="$1"
    shift
    echo "$*"
}
split_words() {
    local IFS=$' \t\n'
    local input="$1"
    read -ra parts <<<"$input"
    printf '%s\n' "${parts[@]}"
}

list_env_keys() {
    compgen -e
}
unset_some() {
    unset NOT_SET_VAR
    export -n EXPORTED 2>/dev/null || true
}

seconds_since_epoch() {
    date +%s
}
days_until() {
    local target="$1"
    local now then
    now=$(date +%s)
    then=$(date -d "$target" +%s 2>/dev/null || echo "$now")
    echo $(( (then - now) / 86400 ))
}

to_decimal() {
    local raw="$1"
    case "$raw" in
        0x*|0X*) printf '%d\n' "$raw" ;;
        0[0-7]*) printf '%d\n' "$raw" ;;
        *) printf '%d\n' "$raw" ;;
    esac
}

emit_record() {
    local id="$1" name="$2"
    printf '{"id":%d,"name":%s}\n' "$id" "${name@Q}"
}

ping_coproc() {
    coproc PING { sleep 0.05; echo pong; }
    if read -t 1 -r resp <&"${PING[0]}"; then
        echo "$resp" >/dev/null
    fi
    wait "$PING_PID" 2>/dev/null || true
}

on_return() {
    echo "leaving ${FUNCNAME[1]}" >/dev/null
}
return_trap_demo() {
    trap 'on_return' RETURN
    local _x=1
    trap - RETURN
}

self_test() {
    greet 'tester' >/dev/null
    square 7 >/dev/null
    div 10 2 >/dev/null
    classify hello.zip >/dev/null
    classify archive.tar.gz >/dev/null
    parse_args -v -i in -o out rest1 rest2 >/dev/null
    join_words ',' a b c >/dev/null
    ping_coproc
    return_trap_demo
}

main() {
    self_test
    echo 'hello world'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi

function legacy_keyword_form {
    echo 'function-keyword form'
}
function modern_paren_form() {
    echo 'function-keyword + paren form'
}
short_form() {
    echo 'short form'
}

fetch_url() {
    local url="$1"
    if command -v curl >/dev/null; then
        curl -fsSL --max-time 10 "$url"
    elif command -v wget >/dev/null; then
        wget -qO- --timeout=10 "$url"
    elif (( BASH_VERSINFO[0] >= 4 )); then
        local host path
        host="${url#*://}"
        host="${host%%/*}"
        path="/${url#*://*/}"
        exec 3<>"/dev/tcp/$host/80"
        printf 'GET %s HTTP/1.0\r\nHost: %s\r\n\r\n' "$path" "$host" >&3
        cat <&3
        exec 3<&-
    else
        return 1
    fi
}

descriptor_dance() {
    exec 5>/dev/null
    exec 6>&1
    exec 1>&5
    echo 'this goes to fd 5 (now stdout)' >/dev/null
    exec 1>&6
    exec 5>&-
    exec 6>&-
}

all_lowercase() {
    [[ "$1" =~ ^[a-z]+$ ]]
}
hex_digits_only() {
    [[ "$1" =~ ^[0-9a-fA-F]+$ ]]
}
ends_with() {
    [[ "$1" == *"$2" ]]
}
starts_with() {
    [[ "$1" == "$2"* ]]
}
contains() {
    [[ "$1" == *"$2"* ]]
}

pad_zero() {
    printf '%05d\n' "$1"
}
hex_format() {
    printf '0x%08X\n' "$1"
}
binary_str() {
    local n="$1"
    local out=''
    while (( n > 0 )); do
        out="$((n % 2))$out"
        n=$((n / 2))
    done
    [[ -z "$out" ]] && out='0'
    echo "$out"
}

slice_pop_back() {
    local -n arr_ref="$1"
    local last="${arr_ref[-1]}"
    arr_ref=( "${arr_ref[@]:0:${#arr_ref[@]}-1}" )
    echo "$last"
}
slice_pop_front() {
    local -n arr_ref="$1"
    local first="${arr_ref[0]}"
    arr_ref=( "${arr_ref[@]:1}" )
    echo "$first"
}
arr_reverse() {
    local -n arr_ref="$1"
    local len="${#arr_ref[@]}" tmp
    local -i i j
    for (( i = 0, j = len - 1; i < j; i++, j-- )); do
        tmp="${arr_ref[$i]}"
        arr_ref[$i]="${arr_ref[$j]}"
        arr_ref[$j]="$tmp"
    done
}
arr_contains() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        [[ "$item" == "$needle" ]] && return 0
    done
    return 1
}

require_bash() {
    local needed_major="$1"
    if (( BASH_VERSINFO[0] < needed_major )); then
        echo "needs bash $needed_major+, have ${BASH_VERSION}" >&2
        return 1
    fi
}

acquire_lock() {
    local lockfile="$1"
    local timeout="${2:-30}"
    local waited=0
    while ! ( set -C; echo "$$" >"$lockfile" ) 2>/dev/null; do
        sleep 1
        waited=$((waited + 1))
        if (( waited >= timeout )); then
            return 1
        fi
    done
    trap "rm -f '$lockfile'" EXIT
}

process_lines() {
    local input="$1"
    while IFS= read -r line; do
        printf 'got: %s\n' "$line"
    done <"$input"
}

shopt -s lastpipe 2>/dev/null || true
sum_lines_pipe() {
    local total=0 line
    seq 1 10 | while read -r line; do
        total=$((total + line))
    done
    echo "$total"
}

walk_pgrp() {
    local pid="${1:-$$}"
    local depth="${2:-0}"
    local indent=''
    local _i
    for ((_i = 0; _i < depth; _i++)); do
        indent+='  '
    done
    echo "${indent}${pid}"
    local child
    for child in $(pgrep -P "$pid" 2>/dev/null); do
        walk_pgrp "$child" $((depth + 1))
    done
}

declare -A SET_STORE
set_add() {
    SET_STORE["$1"]=1
}
set_has() {
    [[ -n "${SET_STORE[$1]+_}" ]]
}
set_remove() {
    unset 'SET_STORE['$1']'
}
set_size() {
    echo "${#SET_STORE[@]}"
}
set_iter() {
    local k
    for k in "${!SET_STORE[@]}"; do
        printf '%s\n' "$k"
    done
}

declare -A MEMO_FIB
fib_memo() {
    local n="$1"
    if (( n < 2 )); then
        echo "$n"
        return 0
    fi
    if [[ -n "${MEMO_FIB[$n]+_}" ]]; then
        echo "${MEMO_FIB[$n]}"
        return 0
    fi
    local a b sum
    a="$(fib_memo $((n - 1)))"
    b="$(fib_memo $((n - 2)))"
    sum=$((a + b))
    MEMO_FIB["$n"]="$sum"
    echo "$sum"
}

fifo_demo() {
    local fifo
    fifo="$(mktemp -u)"
    mkfifo "$fifo"
    ( while read -r ln; do
          [[ -z "$ln" ]] && break
          echo "consumer: $ln"
      done <"$fifo" ) &
    local cpid=$!
    {
        echo 'one'
        echo 'two'
        echo ''
    } >"$fifo"
    wait "$cpid" 2>/dev/null || true
    rm -f "$fifo"
}

declare -A Person
Person_init() {
    Person[name]="$1"
    Person[age]="$2"
}
Person_greet() {
    printf 'I am %s, %s years old\n' "${Person[name]}" "${Person[age]}"
}
Person_birthday() {
    Person[age]=$(( ${Person[age]} + 1 ))
}

chain_trap() {
    local cur next
    cur="$(trap -p EXIT | sed -n "s/^trap -- '\(.*\)' EXIT\$/\1/p")"
    next="echo 'extra exit hook'; ${cur:-true}"
    trap "$next" EXIT
}

