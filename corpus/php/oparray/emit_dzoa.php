<?php

const DZOA_MAGIC = "DZOA";
const DZOA_VERSION = 3;

const OT_UNUSED = 0;
const OT_CONST = 1;
const OT_TMP = 2;
const OT_VAR = 4;
const OT_CV = 8;

const K_MAIN = 0;
const K_FUNCTION = 1;
const K_METHOD = 2;
const K_CLOSURE = 3;

const L_NULL = 0;
const L_BOOL = 1;
const L_LONG = 2;
const L_DOUBLE = 3;
const L_STR = 4;
const L_ARRAY = 5;
const L_SWITCH_LONG = 6;
const L_SWITCH_STRING = 7;

const SWITCH_TABLE_CAP = 65536;
const SWITCH_KEY_BYTES_CAP = 1048576;

const OPMAP = [
    'NOP' => 0,
    'ADD' => 1,
    'SUB' => 2,
    'MUL' => 3,
    'DIV' => 4,
    'MOD' => 5,
    'SL' => 6,
    'SR' => 7,
    'CONCAT' => 8,
    'FAST_CONCAT' => 8,
    'BW_OR' => 9,
    'BW_AND' => 10,
    'BW_XOR' => 11,
    'POW' => 12,
    'BW_NOT' => 13,
    'BOOL_NOT' => 14,
    'IS_IDENTICAL' => 16,
    'IS_NOT_IDENTICAL' => 17,
    'IS_EQUAL' => 18,
    'IS_NOT_EQUAL' => 19,
    'IS_SMALLER' => 20,
    'IS_SMALLER_OR_EQUAL' => 21,
    'ASSIGN' => 22,
    'ASSIGN_DIM' => 23,
    'ASSIGN_OBJ' => 24,
    'ASSIGN_OP' => 26,
    'QM_ASSIGN' => 31,
    'PRE_INC' => 34,
    'PRE_DEC' => 35,
    'POST_INC' => 36,
    'POST_DEC' => 37,
    'JMP' => 42,
    'JMPZ' => 43,
    'JMPNZ' => 44,
    'JMPZ_EX' => 46,
    'JMPNZ_EX' => 47,
    'CASE' => 48,
    'CAST' => 51,
    'BOOL' => 52,
    'INIT_FCALL_BY_NAME' => 59,
    'DO_FCALL' => 60,
    'INIT_FCALL' => 61,
    'RETURN' => 62,
    'RECV' => 63,
    'RECV_INIT' => 64,
    'SEND_VAL' => 65,
    'SEND_VAR_EX' => 66,
    'NEW' => 68,
    'INIT_NS_FCALL_BY_NAME' => 69,
    'FREE' => 70,
    'INIT_ARRAY' => 71,
    'ADD_ARRAY_ELEMENT' => 72,
    'INCLUDE_OR_EVAL' => 73,
    'UNSET_VAR' => 74,
    'FE_RESET_R' => 77,
    'FE_FETCH_R' => 78,
    'EXIT' => 79,
    'FETCH_R' => 80,
    'FETCH_DIM_R' => 81,
    'FETCH_OBJ_R' => 82,
    'FETCH_W' => 83,
    'FETCH_RW' => 86,
    'FETCH_CONSTANT' => 99,
    'CATCH' => 107,
    'THROW' => 108,
    'FETCH_CLASS' => 109,
    'CLONE' => 110,
    'RETURN_BY_REF' => 111,
    'INIT_METHOD_CALL' => 112,
    'INIT_STATIC_METHOD_CALL' => 113,
    'ISSET_ISEMPTY_VAR' => 114,
    'ISSET_ISEMPTY_DIM_OBJ' => 115,
    'SEND_VAL_EX' => 116,
    'SEND_VAR' => 117,
    'FE_RESET_RW' => 125,
    'FE_FETCH_RW' => 126,
    'DO_ICALL' => 129,
    'DO_UCALL' => 130,
    'DO_FCALL_BY_NAME' => 131,
    'ECHO' => 136,
    'OP_DATA' => 137,
    'INSTANCEOF' => 138,
    'DECLARE_FUNCTION' => 141,
    'DECLARE_LAMBDA_FUNCTION' => 142,
    'DECLARE_CONST' => 143,
    'DECLARE_CLASS' => 144,
    'DECLARE_CLASS_DELAYED' => 145,
    'DECLARE_ANON_CLASS' => 146,
    'ISSET_ISEMPTY_PROP_OBJ' => 148,
    'HANDLE_EXCEPTION' => 149,
    'JMP_SET' => 152,
    'ISSET_ISEMPTY_CV' => 154,
    'YIELD' => 160,
    'GENERATOR_RETURN' => 161,
    'YIELD_FROM' => 166,
    'COALESCE' => 169,
    'SWITCH_LONG' => 187,
    'SWITCH_STRING' => 188,
    'MATCH' => 195,
    'JMP_NULL' => 198,
    'STRLEN' => 210,
    'COUNT' => 211,
    'VERIFY_RETURN_TYPE' => 212,
    'FE_FREE' => 213,
    'GENERATOR_CREATE' => 214,
    'SEND_VAR_NO_REF_EX' => 117,
    'SEND_FUNC_ARG' => 117,
];

const CAST_TYPE_MAP = [
    'null' => 1,
    'bool' => 18,
    'long' => 4,
    'double' => 5,
    'string' => 6,
    'array' => 7,
    'object' => 8,
];

const ISSET_FLAG_MAP = [
    'isset' => 0,
    'empty' => 1,
];

const ARG_COUNT_PREFIXED = [
    'INIT_METHOD_CALL' => 2,
    'INIT_STATIC_METHOD_CALL' => 2,
    'NEW' => 1,
];

const ASSIGN_OP_MAP = [
    'ADD' => 1,
    'SUB' => 2,
    'MUL' => 3,
    'DIV' => 4,
    'MOD' => 5,
    'CONCAT' => 8,
    'POW' => 12,
    'SL' => 6,
    'SR' => 7,
    'BW_OR' => 9,
    'BW_AND' => 10,
    'BW_XOR' => 11,
];

final class LiteralPool
{
    private array $items = [];
    private array $index = [];

    public function intern(string $tag, $value): int
    {
        $key = $tag . '|' . var_export($value, true);
        if (isset($this->index[$key])) {
            return $this->index[$key];
        }
        $idx = count($this->items);
        $this->items[] = [$tag, $value];
        $this->index[$key] = $idx;

        return $idx;
    }

    public function items(): array
    {
        return $this->items;
    }
}

final class ParsedOp
{
    public int $opcode = 0;
    public int $op1Type = OT_UNUSED;
    public int $op2Type = OT_UNUSED;
    public int $resultType = OT_UNUSED;
    public int $op1 = 0;
    public int $op2 = 0;
    public int $result = 0;
    public int $ext = 0;
    public int $line = 0;
    public ?string $switchKind = null;
    public array $switchEntries = [];
    public ?int $switchDefault = null;
}

final class ParsedOpArray
{
    public int $kind = K_MAIN;
    public ?string $name = null;
    public ?string $className = null;
    public int $numArgs = 0;
    public LiteralPool $pool;
    public array $ops = [];
    public array $children = [];
    public array $vars = [];

    public function __construct()
    {
        $this->pool = new LiteralPool();
    }
}

function fail(string $msg): never
{
    fwrite(STDERR, "emit_dzoa: $msg\n");
    exit(3);
}

function parse_operand(string $tok, ParsedOpArray $oa): array
{
    $tok = trim($tok);
    if ($tok === '' || $tok === 'NEXT' || $tok === 'THIS') {
        return [OT_UNUSED, 0];
    }
    if (preg_match('/^CV(\d+)(?:\(\$([^)]*)\))?/', $tok, $m)) {
        $slot = (int) $m[1];
        if (isset($m[2]) && $m[2] !== '' && !isset($oa->vars[$slot])) {
            $oa->vars[$slot] = $m[2];
        }
        return [OT_CV, $slot];
    }
    if (preg_match('/^T(\d+)$/', $tok, $m)) {
        return [OT_TMP, (int) $m[1]];
    }
    if (preg_match('/^V(\d+)$/', $tok, $m)) {
        return [OT_VAR, (int) $m[1]];
    }
    if (preg_match('/^int\((-?\d+)\)$/', $tok, $m)) {
        return [OT_CONST, $oa->pool->intern('long', (int) $m[1])];
    }
    if (preg_match('/^float\(([^)]+)\)$/', $tok, $m) || preg_match('/^double\(([^)]+)\)$/', $tok, $m)) {
        return [OT_CONST, $oa->pool->intern('double', (float) $m[1])];
    }
    if ($tok === 'null') {
        return [OT_CONST, $oa->pool->intern('null', null)];
    }
    if ($tok === 'true') {
        return [OT_CONST, $oa->pool->intern('bool', true)];
    }
    if ($tok === 'false') {
        return [OT_CONST, $oa->pool->intern('bool', false)];
    }
    if (preg_match('/^bool\((true|false)\)$/', $tok, $m)) {
        return [OT_CONST, $oa->pool->intern('bool', $m[1] === 'true')];
    }
    if (preg_match('/^string\("((?:[^"\\\\]|\\\\.)*)"\)$/s', $tok, $m)) {
        return [OT_CONST, $oa->pool->intern('string', stripcslashes($m[1]))];
    }
    if (str_starts_with($tok, 'array(')) {
        return [OT_CONST, $oa->pool->intern('array', 0)];
    }
    return [null, $tok];
}

function le32(int $v): string
{
    return pack('V', $v & 0xffffffff);
}

function le64(int $v): string
{
    return pack('P', $v);
}

function push_string(string $s): string
{
    return le32(strlen($s)) . $s;
}

function push_opt_string(?string $s): string
{
    if ($s === null) {
        return "\x00";
    }
    return "\x01" . push_string($s);
}

function serialize_var_names(array $vars): string
{
    if ($vars === []) {
        return le32(0);
    }
    $count = max(array_keys($vars)) + 1;
    $out = le32($count);
    for ($slot = 0; $slot < $count; $slot++) {
        $out .= push_opt_string($vars[$slot] ?? null);
    }

    return $out;
}

function serialize_literals(LiteralPool $pool, int $schemaVersion): string
{
    $items = $pool->items();
    $out = le32(count($items));
    foreach ($items as [$tag, $value]) {
        switch ($tag) {
            case 'null':
                $out .= chr(L_NULL);
                break;
            case 'bool':
                $out .= chr(L_BOOL) . ($value ? "\x01" : "\x00");
                break;
            case 'long':
                $out .= chr(L_LONG) . le64($value);
                break;
            case 'double':
                $out .= chr(L_DOUBLE) . pack('d', $value);
                break;
            case 'string':
                $out .= chr(L_STR) . push_string($value);
                break;
            case 'array':
                $out .= chr(L_ARRAY) . le32($value);
                break;
            case 'switch-long':
                if ($schemaVersion < 3) {
                    fail("DZOA schema version $schemaVersion cannot encode SWITCH_LONG targets");
                }
                $out .= chr(L_SWITCH_LONG) . le32(count($value));
                foreach ($value as [$key, $target]) {
                    $out .= le64($key) . le32($target);
                }
                break;
            case 'switch-string':
                if ($schemaVersion < 3) {
                    fail("DZOA schema version $schemaVersion cannot encode SWITCH_STRING targets");
                }
                $out .= chr(L_SWITCH_STRING) . le32(count($value));
                foreach ($value as [$key, $target]) {
                    $out .= push_string($key) . le32($target);
                }
                break;
            default:
                fail("unknown literal tag $tag");
        }
    }

    return $out;
}

function serialize_body(ParsedOpArray $oa, int $schemaVersion): string
{
    $out = chr($oa->kind);
    $out .= push_opt_string($oa->name);
    $out .= push_opt_string($oa->className);
    $out .= le32($oa->numArgs);
    if ($schemaVersion >= 2) {
        $out .= serialize_var_names($oa->vars);
    }
    $out .= serialize_literals($oa->pool, $schemaVersion);
    $out .= le32(count($oa->ops));
    foreach ($oa->ops as $op) {
        $out .= chr($op->opcode);
        $out .= chr($op->op1Type);
        $out .= chr($op->op2Type);
        $out .= chr($op->resultType);
        $out .= le32($op->op1);
        $out .= le32($op->op2);
        $out .= le32($op->result);
        $out .= le32($op->ext);
        $out .= le32($op->line);
    }
    $out .= le32(count($oa->children));
    foreach ($oa->children as $child) {
        $out .= serialize_body($child, $schemaVersion);
    }

    return $out;
}

function tokenize_operands(string $rest): array
{
    $tokens = [];
    $len = strlen($rest);
    $i = 0;
    while ($i < $len) {
        while ($i < $len && $rest[$i] === ' ') {
            $i++;
        }
        if ($i >= $len) {
            break;
        }
        $start = $i;
        $depth = 0;
        $inStr = false;
        while ($i < $len) {
            $c = $rest[$i];
            if ($inStr) {
                if ($c === '\\') {
                    $i += 2;
                    continue;
                }
                if ($c === '"') {
                    $inStr = false;
                }
                $i++;
                continue;
            }
            if ($c === '"') {
                $inStr = true;
                $i++;
                continue;
            }
            if ($c === '(') {
                $depth++;
                $i++;
                continue;
            }
            if ($c === ')') {
                $depth--;
                $i++;
                continue;
            }
            if ($c === ' ' && $depth === 0) {
                break;
            }
            $i++;
        }
        $tokens[] = substr($rest, $start, $i - $start);
    }

    return $tokens;
}

function build_op(string $mnemonic, array $resultTok, array $operands, ParsedOpArray $oa, int $line): ParsedOp
{
    $op = new ParsedOp();
    $op->line = $line;

    if (str_starts_with($mnemonic, 'ASSIGN_') && isset(ASSIGN_OP_MAP[substr($mnemonic, 7)])) {
        $op->opcode = OPMAP['ASSIGN_OP'];
        $op->ext = ASSIGN_OP_MAP[substr($mnemonic, 7)];
    } elseif (!isset(OPMAP[$mnemonic])) {
        fail("unmapped opcode '$mnemonic' (line $line); extend OPMAP or restrict the sample");
    } else {
        $op->opcode = OPMAP[$mnemonic];
    }

    [$rt, $rv] = $resultTok;
    if ($rt !== null && $rt !== OT_UNUSED) {
        $op->resultType = $rt;
        $op->result = $rv;
    }

    $parsed = [];
    foreach ($operands as $tok) {
        $parsed[] = parse_operand($tok, $oa);
    }

    if (isset($parsed[0]) && $parsed[0][0] !== null) {
        $op->op1Type = $parsed[0][0];
        $op->op1 = $parsed[0][1];
    }
    if (isset($parsed[1]) && $parsed[1][0] !== null) {
        $op->op2Type = $parsed[1][0];
        $op->op2 = $parsed[1][1];
    }

    return $op;
}

function rejoin_string_operands(array $rawLines): array
{
    $lines = [];
    $i = 0;
    $count = count($rawLines);
    while ($i < $count) {
        $line = $rawLines[$i];
        $quoteCount = substr_count($line, '"') - substr_count($line, '\\"');
        while (($quoteCount % 2) === 1 && $i + 1 < $count) {
            $i++;
            $line .= "\n" . $rawLines[$i];
            $quoteCount = substr_count($line, '"') - substr_count($line, '\\"');
        }
        $lines[] = $line;
        $i++;
    }

    return $lines;
}

function build_switch_op(
    string $mnemonic,
    array $tokens,
    ParsedOpArray $oa,
    int $address
): ParsedOp {
    $subjectToken = array_shift($tokens);
    if ($subjectToken === null) {
        fail("$mnemonic at line $address has no subject");
    }
    [$subjectType, $subjectValue] = parse_operand($subjectToken, $oa);
    if ($subjectType === null || $subjectType === OT_UNUSED) {
        fail("$mnemonic at line $address has an unparseable subject '$subjectToken'");
    }
    if (count($tokens) < 4 || (count($tokens) % 2) !== 0) {
        fail("$mnemonic at line $address has an incomplete dispatch table");
    }
    $entryCount = intdiv(count($tokens), 2) - 1;
    if ($entryCount < 1 || $entryCount > SWITCH_TABLE_CAP) {
        fail("$mnemonic at line $address carries $entryCount entries, cap " . SWITCH_TABLE_CAP);
    }
    $entries = [];
    $seen = [];
    $default = null;
    $tableKind = null;
    $keyBytes = 0;
    while ($tokens !== []) {
        $keyToken = array_shift($tokens);
        $targetToken = array_shift($tokens);
        if ($keyToken === null || $targetToken === null) {
            fail("$mnemonic at line $address has an incomplete key-target pair");
        }
        $targetToken = rtrim($targetToken, ',');
        if (!preg_match('/^\d+$/', $targetToken)) {
            fail("$mnemonic at line $address has an invalid target '$targetToken'");
        }
        $target = (int) $targetToken;
        if ($keyToken === 'default:') {
            if ($default !== null || $tokens !== []) {
                fail("$mnemonic at line $address has an ambiguous default target");
            }
            $default = $target;
            continue;
        }
        $longKey = preg_match('/^(-?\d+):$/', $keyToken, $match) === 1;
        $stringKey = preg_match('/^"((?:[^"\\\\]|\\\\.)*)":$/s', $keyToken, $stringMatch) === 1;
        if ($mnemonic === 'SWITCH_LONG' || ($mnemonic === 'MATCH' && $longKey)) {
            if (!$longKey || $tableKind === 'switch-string') {
                fail("$mnemonic at line $address has a non-integer key '$keyToken'");
            }
            $tableKind = 'switch-long';
            $key = (int) $match[1];
            $identity = 'i:' . $match[1];
        } else {
            if (!$stringKey || $tableKind === 'switch-long') {
                fail("$mnemonic at line $address has a non-string key '$keyToken'");
            }
            $tableKind = 'switch-string';
            $key = stripcslashes($stringMatch[1]);
            $keyBytes += strlen($key) + 1;
            if ($keyBytes > SWITCH_KEY_BYTES_CAP) {
                fail("$mnemonic at line $address exceeds string-key byte cap " . SWITCH_KEY_BYTES_CAP);
            }
            $identity = 's:' . $key;
        }
        if (isset($seen[$identity])) {
            fail("$mnemonic at line $address repeats key '$keyToken'");
        }
        $seen[$identity] = true;
        $entries[] = [$key, $target];
    }
    if ($default === null || count($entries) !== $entryCount) {
        fail("$mnemonic at line $address has no exact default target");
    }
    $op = new ParsedOp();
    $op->opcode = OPMAP[$mnemonic];
    $op->op1Type = $subjectType;
    $op->op1 = $subjectValue;
    $op->line = $address + 1;
    $op->switchKind = $tableKind;
    $op->switchEntries = $entries;
    $op->switchDefault = $default;

    return $op;
}

function parse_dump(string $text): array
{
    $lines = rejoin_string_operands(preg_split('/\r\n|\n|\r/', $text));
    $arrays = [];
    $current = null;
    $nameToArray = [];
    $blockDone = false;

    $flush = function () use (&$current, &$arrays, &$nameToArray): void {
        if ($current !== null) {
            $arrays[] = $current;
            $nameToArray[$current['oa']->name ?? '$_main'] = count($arrays) - 1;
            $current = null;
        }
    };

    foreach ($lines as $raw) {
        $line = rtrim($raw);
        if ($line === '') {
            continue;
        }
        if (preg_match('/^(LIVE RANGES|EXCEPTION TABLE)/', $line)) {
            $blockDone = true;
            continue;
        }
        if (preg_match('/^(\S+):\s*$/', $line, $m)
            && !preg_match('/^\d{4}$/', $m[1])) {
            $blockDone = false;
            $flush();
            $oa = new ParsedOpArray();
            $rawName = trim($m[1]);
            if ($rawName === '$_main') {
                $oa->kind = K_MAIN;
            } elseif (str_contains($rawName, '::')) {
                $oa->kind = K_METHOD;
                [$cls, $meth] = explode('::', $rawName, 2);
                $oa->className = $cls;
                $oa->name = $meth;
            } elseif (str_starts_with($rawName, '{closure')) {
                $oa->kind = K_CLOSURE;
                $oa->name = null;
            } else {
                $oa->kind = K_FUNCTION;
                $oa->name = $rawName;
            }
            $current = ['oa' => $oa, 'index' => [], 'jmp' => []];
            continue;
        }
        if ($current === null || $blockDone) {
            continue;
        }
        if (preg_match('/^\s*;.*\(lines=\d+,\s*args=(\d+)/', $line, $m)) {
            $current['oa']->numArgs = (int) $m[1];
            continue;
        }
        if (preg_match('/^\s*;/', $line)) {
            continue;
        }
        if (preg_match('/^(LIVE RANGES|EXCEPTION TABLE)/', $line)) {
            continue;
        }
        if (preg_match('/^\s+\d+:\s/', $line)) {
            continue;
        }

        if (!preg_match('/^(\d{4})\s+(.*)$/s', trim($line), $m)) {
            continue;
        }
        $addr = (int) $m[1];
        $body = trim($m[2]);

        $resultTok = [OT_UNUSED, 0];
        if (preg_match('/^(CV\d+\([^)]*\)|T\d+|V\d+)\s*=\s*(.*)$/s', $body, $mm)) {
            $resultTok = parse_operand($mm[1], $current['oa']);
            $body = trim($mm[2]);
        }

        if (!preg_match('/^([A-Z_]+)(?:\s+(.*))?$/s', $body, $mm)) {
            continue;
        }
        $mnemonic = $mm[1];
        $rest = isset($mm[2]) ? trim($mm[2]) : '';

        if ($mnemonic === 'OP_DATA') {
            $op = new ParsedOp();
            $op->opcode = OPMAP['OP_DATA'] ?? 137;
            $op->line = $addr + 1;
            $tokens = tokenize_operands($rest);
            if (isset($tokens[0])) {
                [$t, $v] = parse_operand($tokens[0], $current['oa']);
                if ($t !== null && $t !== OT_UNUSED) {
                    $op->op1Type = $t;
                    $op->op1 = $v;
                }
            }
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        $tokens = tokenize_operands($rest);

        if ($mnemonic === 'SWITCH_LONG' || $mnemonic === 'SWITCH_STRING' || $mnemonic === 'MATCH') {
            $op = build_switch_op($mnemonic, $tokens, $current['oa'], $addr);
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        $isFcallInit = in_array($mnemonic, ['INIT_FCALL', 'INIT_FCALL_BY_NAME', 'INIT_NS_FCALL_BY_NAME'], true);
        if ($isFcallInit) {
            $nameTok = end($tokens);
            $op = build_op($mnemonic, [OT_UNUSED, 0], [], $current['oa'], $addr + 1);
            [$t, $v] = parse_operand($nameTok ?: '', $current['oa']);
            if ($t !== null) {
                $op->op2Type = $t;
                $op->op2 = $v;
            }
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        if (isset(ARG_COUNT_PREFIXED[$mnemonic])) {
            $operandCount = ARG_COUNT_PREFIXED[$mnemonic];
            $countTok = array_shift($tokens);
            if (!is_numeric($countTok)) {
                fail("$mnemonic at line $addr does not lead with an argument count: '$countTok'");
            }
            if (count($tokens) !== $operandCount) {
                fail("$mnemonic at line $addr carries " . count($tokens) . " operands, expected $operandCount");
            }
            $op = build_op($mnemonic, $resultTok, $tokens, $current['oa'], $addr + 1);
            $op->ext = (int) $countTok;
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        if ($mnemonic === 'CAST' || str_starts_with($mnemonic, 'ISSET_ISEMPTY_')) {
            $flagTok = array_shift($tokens);
            if ($flagTok === null || !preg_match('/^\(([a-z_]+)\)$/', $flagTok, $fm)) {
                fail("$mnemonic at line $addr does not lead with a parenthesized mode: '" . (string) $flagTok . "'");
            }
            $table = $mnemonic === 'CAST' ? CAST_TYPE_MAP : ISSET_FLAG_MAP;
            if (!isset($table[$fm[1]])) {
                fail("$mnemonic at line $addr uses unmapped mode '{$fm[1]}'");
            }
            $op = build_op($mnemonic, $resultTok, $tokens, $current['oa'], $addr + 1);
            $op->ext = $table[$fm[1]];
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        $isSend = str_starts_with($mnemonic, 'SEND_');
        if ($isSend) {
            $valueTok = $tokens[0] ?? '';
            $op = build_op('SEND_VAL', [OT_UNUSED, 0], [$valueTok], $current['oa'], $addr + 1);
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        if ($mnemonic === 'INIT_ARRAY' || $mnemonic === 'ADD_ARRAY_ELEMENT') {
            $valueOperands = array_values(array_filter($tokens, static function (string $t): bool {
                return $t !== '(packed)' && $t !== '(hash)' && !preg_match('/^\d+$/', $t);
            }));
            $op = build_op($mnemonic, $resultTok, $valueOperands, $current['oa'], $addr + 1);
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        $isSimpleFetch = in_array($mnemonic, ['FETCH_R', 'FETCH_W', 'FETCH_RW'], true);
        if ($isSimpleFetch) {
            $nameOperands = array_values(array_filter($tokens, static function (string $t): bool {
                return !preg_match('/^\((?:local|global|static)\)$/', trim($t));
            }));
            $op = build_op($mnemonic, $resultTok, $nameOperands, $current['oa'], $addr + 1);
            $current['oa']->ops[] = $op;
            $current['index'][$addr] = count($current['oa']->ops) - 1;
            continue;
        }

        $isJmp = in_array($mnemonic, ['JMP', 'JMPZ', 'JMPNZ', 'JMPZ_EX', 'JMPNZ_EX', 'COALESCE', 'JMP_SET', 'JMP_NULL'], true);
        $isLoopCtl = in_array($mnemonic, ['FE_RESET_R', 'FE_RESET_RW', 'FE_FETCH_R', 'FE_FETCH_RW', 'FE_FREE'], true);

        $op = build_op($mnemonic, $resultTok, $tokens, $current['oa'], $addr + 1);

        if ($isJmp) {
            $targetTok = end($tokens);
            $op->op1Type = OT_UNUSED;
            $op->op2Type = OT_UNUSED;
            if ($mnemonic === 'JMP') {
                $current['jmp'][] = [count($current['oa']->ops), 'op1', (int) $targetTok];
            } else {
                [$t, $v] = parse_operand($tokens[0], $current['oa']);
                $op->op1Type = $t ?? OT_UNUSED;
                $op->op1 = $v ?? 0;
                $current['jmp'][] = [count($current['oa']->ops), 'op2', (int) $targetTok];
            }
        } elseif ($isLoopCtl) {
            $op->op1Type = OT_UNUSED;
            $op->op1 = 0;
            $op->op2Type = OT_UNUSED;
            $op->op2 = 0;
            $op->resultType = OT_UNUSED;
            $op->result = 0;
            if ($mnemonic === 'FE_FREE') {
                $op->opcode = OPMAP['FE_FREE'];
                [$t0, $v0] = parse_operand($tokens[0] ?? '', $current['oa']);
                if ($t0 !== null) {
                    $op->op1Type = $t0;
                    $op->op1 = $v0;
                }
            } elseif ($mnemonic === 'FE_RESET_R' || $mnemonic === 'FE_RESET_RW') {
                [$t0, $v0] = parse_operand($tokens[0] ?? '', $current['oa']);
                if ($t0 !== null) {
                    $op->op1Type = $t0;
                    $op->op1 = $v0;
                }
                [$rt, $rv] = $resultTok;
                if ($rt !== null && $rt !== OT_UNUSED) {
                    $op->resultType = $rt;
                    $op->result = $rv;
                }
                $targetTok = end($tokens);
                if (is_numeric($targetTok)) {
                    $current['jmp'][] = [count($current['oa']->ops), 'op2', (int) $targetTok];
                }
            } else {
                [$t0, $v0] = parse_operand($tokens[0] ?? '', $current['oa']);
                if ($t0 !== null) {
                    $op->op1Type = $t0;
                    $op->op1 = $v0;
                }
                $valueTok = $tokens[1] ?? '';
                [$vt, $vv] = parse_operand($valueTok, $current['oa']);
                if ($vt !== null && $vt !== OT_UNUSED) {
                    $op->op2Type = $vt;
                    $op->op2 = $vv;
                }
                [$rt, $rv] = $resultTok;
                if ($rt !== null && $rt !== OT_UNUSED) {
                    $op->resultType = $rt;
                    $op->result = $rv;
                    $op->ext = 1;
                }
            }
        }

        $current['oa']->ops[] = $op;
        $current['index'][$addr] = count($current['oa']->ops) - 1;
    }
    $flush();

    foreach ($arrays as &$entry) {
        $oa = $entry['oa'];
        foreach ($entry['jmp'] as [$opPos, $field, $targetAddr]) {
            $resolved = $entry['index'][$targetAddr] ?? null;
            if ($resolved === null) {
                $resolved = count($oa->ops);
            }
            if ($field === 'op1') {
                $oa->ops[$opPos]->op1 = $resolved;
                $oa->ops[$opPos]->op1Type = OT_UNUSED;
            } else {
                $oa->ops[$opPos]->op2 = $resolved;
            }
        }
        foreach ($oa->ops as $op) {
            if ($op->switchKind === null) {
                continue;
            }
            $resolvedEntries = [];
            foreach ($op->switchEntries as [$key, $targetAddress]) {
                if (!isset($entry['index'][$targetAddress])) {
                    fail("{$op->switchKind} target $targetAddress is outside its op_array");
                }
                $resolvedEntries[] = [$key, $entry['index'][$targetAddress]];
            }
            if ($op->switchDefault === null || !isset($entry['index'][$op->switchDefault])) {
                fail("{$op->switchKind} default target is outside its op_array");
            }
            $op->op2Type = OT_CONST;
            $op->op2 = $oa->pool->intern($op->switchKind, $resolvedEntries);
            $op->ext = $entry['index'][$op->switchDefault];
        }
    }
    unset($entry);

    return $arrays;
}

function nest_arrays(array $arrays): ParsedOpArray
{
    $main = null;
    $children = [];
    foreach ($arrays as $entry) {
        $oa = $entry['oa'];
        if ($oa->kind === K_MAIN) {
            $main = $oa;
        } else {
            $children[] = $oa;
        }
    }
    if ($main === null) {
        fail('no $_main op_array found in dump');
    }
    foreach ($children as $child) {
        $main->children[] = $child;
    }

    return $main;
}

function requires_dzoa_v3(ParsedOpArray $oa): bool
{
    foreach ($oa->ops as $op) {
        if ($op->switchKind !== null) {
            return true;
        }
    }
    foreach ($oa->children as $child) {
        if (requires_dzoa_v3($child)) {
            return true;
        }
    }

    return false;
}

function dump_text(array $stdout_stderr): string
{
    [$stdout, $stderr] = $stdout_stderr;
    if (str_contains($stderr, '$_main:')) {
        return $stderr;
    }
    if (str_contains($stdout, '$_main:')) {
        return $stdout;
    }

    return '';
}

function run_opcache_dump(string $dll, array $iniOverrides, string $srcPath): array
{
    $cmd = [PHP_BINARY, '-d', 'opcache.error_log='];
    if ($dll !== '') {
        $cmd[] = '-d';
        $cmd[] = 'zend_extension=' . $dll;
    }
    foreach ($iniOverrides as $name => $value) {
        $cmd[] = '-d';
        $cmd[] = "$name=$value";
    }
    $cmd[] = '-r';
    $cmd[] = 'opcache_compile_file($argv[1]);';
    $cmd[] = '--';
    $cmd[] = $srcPath;

    $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
    $proc = proc_open($cmd, $descriptors, $pipes);
    if (!is_resource($proc)) {
        fail('could not spawn opcache dump process');
    }
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    proc_close($proc);

    return [$stdout, $stderr];
}

function output_path_key(string $path): string
{
    $resolved = realpath($path);
    if ($resolved === false) {
        $directory = realpath(dirname($path));
        if ($directory !== false) {
            $resolved = $directory . DIRECTORY_SEPARATOR . basename($path);
        } else {
            $resolved = $path;
        }
    }
    if (PHP_OS_FAMILY === 'Windows') {
        return strtolower($resolved);
    }

    return $resolved;
}

function existing_output_identity(string $path): ?string
{
    if (!file_exists($path)) {
        return null;
    }
    clearstatcache(true, $path);
    $metadata = stat($path);
    if ($metadata === false) {
        fail("could not inspect output path $path");
    }

    return (string) $metadata['dev'] . ':' . (string) $metadata['ino'];
}

function require_non_symlink_output(string $path, string $kind): void
{
    if (is_link($path)) {
        fail("$kind output path is a symlink: $path");
    }
}

function require_distinct_outputs(string $outPath, ?string $dumpPath): void
{
    require_non_symlink_output($outPath, 'DZOA');
    if ($dumpPath === null) {
        return;
    }
    require_non_symlink_output($dumpPath, 'raw opcache dump');
    if (output_path_key($outPath) === output_path_key($dumpPath)) {
        fail("DZOA output and raw opcache dump output resolve to the same path $outPath");
    }
    $outIdentity = existing_output_identity($outPath);
    $dumpIdentity = existing_output_identity($dumpPath);
    if ($outIdentity !== null && $outIdentity === $dumpIdentity) {
        fail("DZOA output and raw opcache dump output share one file identity");
    }
}

function write_exact_output(string $path, string $bytes, string $kind): void
{
    $written = file_put_contents($path, $bytes);
    if ($written !== strlen($bytes)) {
        $actual = $written === false ? 'write failure' : (string) $written;
        fail("could not write exact $kind output $path; wrote $actual of " . strlen($bytes) . ' bytes');
    }
}

$srcPath = $argv[1] ?? fail('usage: emit_dzoa.php <source.php> <out.dzoa> [out.dump]');
$outPath = $argv[2] ?? fail('usage: emit_dzoa.php <source.php> <out.dzoa> [out.dump]');
$dumpPath = $argv[3] ?? null;

$opcacheDll = getenv('DZOA_OPCACHE_DLL');
$dll = ($opcacheDll !== false && $opcacheDll !== '') ? $opcacheDll : '';

$baseIni = [
    'opcache.enable' => '1',
    'opcache.enable_cli' => '1',
    'opcache.jit' => 'disable',
    'opcache.jit_buffer_size' => '0',
    'opcache.opt_debug_level' => '0x10000',
];

$configs = [
    $baseIni,
    array_merge($baseIni, ['opcache.optimization_level' => '0xFFFFFFFF']),
    array_merge($baseIni, ['opcache.opt_debug_level' => '0x20000']),
    array_merge($baseIni, [
        'opcache.optimization_level' => '0xFFFFFFFF',
        'opcache.opt_debug_level' => '0x20000',
    ]),
    array_merge($baseIni, [
        'opcache.file_cache_only' => '0',
        'opcache.validate_timestamps' => '0',
    ]),
    array_merge($baseIni, ['opcache.optimization_level' => '0']),
];

$dump = '';
$attempts = [];
foreach ($configs as $ini) {
    $result = run_opcache_dump($dll, $ini, $srcPath);
    $dump = dump_text($result);
    if ($dump !== '') {
        break;
    }
    $attempts[] = sprintf(
        'opt_level=%s opt_debug_level=%s -> stdout[%s] stderr[%s]',
        $ini['opcache.optimization_level'] ?? '(default)',
        $ini['opcache.opt_debug_level'],
        substr(trim($result[0]), 0, 200),
        substr(trim($result[1]), 0, 300)
    );
}

if ($dump === '') {
    fail(
        "no opcache configuration produced a \$_main op_array dump on this php build "
        . '(' . PHP_VERSION . ', dll=' . ($dll === '' ? 'none' : $dll) . '); tried: '
        . implode(' || ', $attempts)
    );
}

$arrays = parse_dump($dump);
$main = nest_arrays($arrays);

$forced = getenv('DZOA_FORCE_VERSION');
$schemaVersion = ($forced !== false && $forced !== '')
    ? (int) $forced
    : (requires_dzoa_v3($main) ? DZOA_VERSION : 2);

$container = DZOA_MAGIC . chr($schemaVersion) . serialize_body($main, $schemaVersion);
require_distinct_outputs($outPath, $dumpPath);
write_exact_output($outPath, $container, 'DZOA');
if ($dumpPath !== null) {
    write_exact_output($dumpPath, $dump, 'raw opcache dump');
}
fwrite(STDOUT, sprintf("wrote %s (%d bytes), %d op_array(s)\n", $outPath, strlen($container), count($arrays)));
