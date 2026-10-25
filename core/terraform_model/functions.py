"""The function subset of the evaluator (Doc 04 §17; C-103).

DAIL implements exactly the functions listed in ``FUNCTIONS`` and no others: every other function
call is unsupported (``function.not_implemented:<name>``, made by the evaluator). Each function
follows the Terraform 1.15 documentation page named in its docstring
(``hashicorp/web-unified-docs`` commit ``fefc7502dba86c70716f0109c324c85829229b2f``,
``content/terraform/v1.15.x/docs/language/functions/<name>.mdx``) and was checked against
``terraform console`` of Terraform 1.15.8 where the page is silent (the report lists them).

A function receives its arguments as values and returns a value. An unknown argument gives an
unknown result; an unsupported argument gives an unsupported result; a reference (``Ref``) names
an ID DAIL does not know, so anything computed from it is unknown, except where the function only
passes the value through (``tostring``, ``concat``, ``merge``, ``flatten`` and so on). Where
Terraform would raise an error, or where DAIL cannot reproduce Terraform exactly (for example
``length`` of a string with non-ASCII characters, which counts grapheme clusters), the function
raises ``Fail`` (the value is unsupported).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable, Sequence
from typing import Final

from core.terraform_model.convert import (
    Fail,
    as_bool,
    as_elements,
    as_int,
    as_mapping,
    as_number,
    as_string,
    kind_of,
    number_text,
    unify,
)
from core.terraform_model.values import (
    FALSE,
    NULL,
    TRUE,
    Known,
    Ref,
    SetValue,
    Unknown,
    Unsupported,
    Value,
    combine_deep,
    known_object,
    known_set,
    walk,
)

FUNCTION_REASONS: Final[dict[str, str]] = {
    "function.not_implemented": "A function outside the subset (the code carries ':<name>').",
    "function.arguments": "A call with a number of arguments the function does not accept.",
    "function.element_empty": "element() of an empty list.",
    "function.lookup_missing": "lookup() of a missing key without a default.",
    "function.coalesce_empty": "coalesce() with no non-null, non-empty argument.",
    "function.non_ascii": "lower() or upper() of a string with non-ASCII characters.",
    "function.unicode_length": "length() of a string with non-ASCII characters (graphemes).",
    "function.format_verb": "format() with a directive other than %s, %d, %v, %%.",
    "function.format_arguments": "format() with a different number of arguments than directives.",
    "function.format_collection": "format() %v of a list or object.",
    "function.cidr": "cidrsubnet() or cidrhost() with an invalid or out-of-range argument.",
    "function.type": "An argument of a type the function does not accept.",
    "operator.collection_equality": "Equality of lists, sets or objects (not modelled).",
}

Function = Callable[[Sequence[Value]], Value]


# --- Propagation helpers -------------------------------------------------------------------------


def derived(ref: Ref) -> Unknown:
    """The value computed from a reference: unknown, because the ID is not known."""
    return Unknown(f"ref.derived:{ref.address}.{ref.attribute}")


def scalar_problem(*values: Value) -> Unknown | Unsupported | None:
    """The first unsupported operand, else the first unknown one (a reference counts as unknown),
    looking at the operands themselves."""
    first: Unknown | None = None
    for value in values:
        if isinstance(value, Unsupported):
            return value
        if first is None:
            if isinstance(value, Unknown):
                first = value
            elif isinstance(value, Ref):
                first = derived(value)
    return first


def deep_problem(*values: Value) -> Unknown | Unsupported | None:
    """Like ``scalar_problem`` but looking inside collections (a reference counts as unknown)."""
    first: Unknown | None = None
    for value in values:
        for item in walk(value):
            if isinstance(item, Unsupported):
                return item
            if first is None:
                if isinstance(item, Unknown):
                    first = item
                elif isinstance(item, Ref):
                    first = derived(item)
    return first


def equal3(left: Value, right: Value) -> bool | None:
    """Terraform equality of two values: True, False, or None when it cannot be decided (an
    unknown operand, or a reference against something that is not the same reference).

    Two references to the same instance are equal, and to different instances are not (distinct
    instances have distinct IDs). Lists, sets and objects raise ``Fail``: DAIL keeps list and
    tuple as one kind, and Terraform's equality tells them apart.
    """
    if isinstance(left, Unsupported | Unknown) or isinstance(right, Unsupported | Unknown):
        return None
    if isinstance(left, Ref) or isinstance(right, Ref):
        if isinstance(left, Ref) and isinstance(right, Ref):
            return left == right
        return None
    kinds = (kind_of(left), kind_of(right))
    if "tuple" in kinds or "set" in kinds or "object" in kinds:
        raise Fail("operator.collection_equality", "equality of collections is not modelled")
    assert isinstance(left, Known) and isinstance(right, Known)
    if kinds[0] != kinds[1]:
        return False
    return bool(left.value == right.value)


# --- Conversion functions ------------------------------------------------------------------------


def _tostring(args: Sequence[Value]) -> Value:
    (value,) = args
    if isinstance(value, Ref):
        return value
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    if kind_of(value) == "null":
        return NULL
    return Known(as_string(value))


def _tonumber(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    if kind_of(value) == "null":
        return NULL
    return Known(as_number(value))


def _tobool(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    if kind_of(value) == "null":
        return NULL
    return TRUE if as_bool(value) else FALSE


def _toset(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    if kind_of(value) == "null":
        return NULL
    return known_set(unify(list(as_elements(value))))


def _tolist(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    if kind_of(value) == "null":
        return NULL
    return Known(tuple(unify(list(as_elements(value)))))


def _tomap(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    if kind_of(value) == "null":
        return NULL
    mapping = as_mapping(value)
    keys = list(mapping)
    return known_object(dict(zip(keys, unify([mapping[k] for k in keys]), strict=True)))


# --- Collection functions ------------------------------------------------------------------------


def _concat(args: Sequence[Value]) -> Value:
    problem = scalar_problem(*args)
    if problem is not None:
        return problem
    items: list[Value] = []
    for arg in args:
        items.extend(as_elements(arg, sets=False))
    return Known(tuple(items))


def _merge(args: Sequence[Value]) -> Value:
    problem = scalar_problem(*args)
    if problem is not None:
        return problem
    merged: dict[str, Value] = {}
    for arg in args:
        if kind_of(arg) == "null":
            continue
        merged.update(as_mapping(arg))
    return known_object(merged)


def _length(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    kind = kind_of(value)
    assert isinstance(value, Known)
    payload = value.value
    if kind == "string":
        if not payload.isascii():
            raise Fail("function.unicode_length", "Terraform counts grapheme clusters")
        return Known(len(payload) - payload.count("\r\n"))
    if kind in ("tuple", "object"):
        return Known(len(payload))
    if kind == "set":
        problem = deep_problem(value)
        return problem if problem is not None else Known(len(payload.elements))
    if kind == "null":
        raise Fail("value.null", "length(null)")
    raise Fail("function.type", f"length of a {kind}")


def _element(args: Sequence[Value]) -> Value:
    collection, index = args
    problem = scalar_problem(collection, index)
    if problem is not None:
        return problem
    items = as_elements(collection, sets=False)
    position = as_int(index)
    if not items:
        raise Fail("function.element_empty", "element() of an empty list")
    return items[position % len(items)]


def _lookup(args: Sequence[Value]) -> Value:
    if len(args) not in (2, 3):
        raise Fail("function.arguments", "lookup takes 2 or 3 arguments")
    mapping_arg, key_arg = args[0], args[1]
    problem = scalar_problem(mapping_arg, key_arg)
    if problem is not None:
        return problem
    mapping = as_mapping(mapping_arg)
    key = as_string(key_arg)
    if key in mapping:
        return mapping[key]
    if len(args) == 3:
        return args[2]
    raise Fail("function.lookup_missing", f"the map has no key {key[:30]!r}")


def _contains(args: Sequence[Value]) -> Value:
    collection, needle = args
    problem = scalar_problem(collection)
    if problem is not None:
        return problem
    if isinstance(needle, Unsupported | Unknown):
        return needle
    elements = as_elements(collection)
    undecided = False
    for element in elements:
        if isinstance(element, Unsupported):
            return element
        answer = equal3(element, needle)
        if answer:
            return TRUE
        if answer is None:
            undecided = True
    if undecided:
        return Unknown("function.contains_undecided")
    return FALSE


def _distinct(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    items = unify(list(as_elements(value, sets=False)))
    problem = combine_deep(*items)
    if problem is not None:
        return problem
    unique: list[Value] = []
    for item in items:
        if not any(equal3(seen, item) for seen in unique):
            unique.append(item)
    return Known(tuple(unique))


def _flatten(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    result: list[Value] = []
    stack = [iter(as_elements(value))]
    while stack:
        for item in stack[-1]:
            if isinstance(item, Known) and isinstance(item.value, tuple | SetValue):
                inner = item.value.elements if isinstance(item.value, SetValue) else item.value
                stack.append(iter(inner))
                break
            if isinstance(item, Unsupported | Unknown):
                return item
            result.append(item)
        else:
            stack.pop()
    return Known(tuple(result))


def _keys(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    return Known(tuple(Known(key) for key in as_mapping(value)))


def _values(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    return Known(tuple(as_mapping(value).values()))


def _coalesce(args: Sequence[Value]) -> Value:
    for candidate in unify(list(args)):
        if isinstance(candidate, Unsupported | Unknown):
            return candidate
        if isinstance(candidate, Ref):
            return candidate
        if candidate.value is None or candidate.value == "":
            continue
        return candidate
    raise Fail("function.coalesce_empty", "no non-null, non-empty argument")


def _compact(args: Sequence[Value]) -> Value:
    (value,) = args
    problem = scalar_problem(value)
    if problem is not None:
        return problem
    items = as_elements(value, sets=False)
    for item in items:
        if isinstance(item, Unsupported | Unknown):
            return item
    kept: list[Value] = []
    for item in items:
        if isinstance(item, Ref):
            kept.append(item)
        elif kind_of(item) == "null":
            continue
        else:
            text = as_string(item)
            if text != "":
                kept.append(Known(text))
    return Known(tuple(kept))


# --- String functions ----------------------------------------------------------------------------


def _case(upper: bool) -> Function:
    def convert(args: Sequence[Value]) -> Value:
        (value,) = args
        problem = scalar_problem(value)
        if problem is not None:
            return problem
        text = as_string(value)
        if not text.isascii():
            raise Fail("function.non_ascii", "Go and Python differ on non-ASCII case mapping")
        return Known(text.upper() if upper else text.lower())

    return convert


def _join(args: Sequence[Value]) -> Value:
    separator, *collections = args
    problem = scalar_problem(separator, *collections)
    if problem is not None:
        return problem
    items = [item for collection in collections for item in as_elements(collection)]
    problem = deep_problem(*items)
    if problem is not None:
        return problem
    return Known(as_string(separator).join(as_string(item) for item in items))


def _split(args: Sequence[Value]) -> Value:
    separator, text = args
    problem = scalar_problem(separator, text)
    if problem is not None:
        return problem
    sep, string = as_string(separator), as_string(text)
    # Go's strings.Split: an empty separator splits after every character (and "" gives no part)
    parts = list(string) if sep == "" else string.split(sep)
    return Known(tuple(Known(part) for part in parts))


def _format(args: Sequence[Value]) -> Value:
    pattern, *rest = args
    problem = scalar_problem(pattern, *rest)
    if problem is not None:
        return problem
    template = as_string(pattern)
    out: list[str] = []
    used = 0
    index = 0
    while index < len(template):
        char = template[index]
        index += 1
        if char != "%":
            out.append(char)
            continue
        if index >= len(template):
            raise Fail("function.format_verb", "a % at the end of the format")
        verb = template[index]
        index += 1
        if verb == "%":
            out.append("%")
            continue
        if verb not in "sdv":
            raise Fail("function.format_verb", f"%{verb} is not implemented")
        if used >= len(rest):
            raise Fail("function.format_arguments", "not enough arguments")
        out.append(_format_one(verb, rest[used]))
        used += 1
    if used != len(rest):
        raise Fail("function.format_arguments", "too many arguments")
    return Known("".join(out))


def _format_one(verb: str, value: Value) -> str:
    kind = kind_of(value)
    if verb == "d":
        number = as_number(value)
        if not isinstance(number, int):
            raise Fail("number.not_integer", f"%d of {number_text(number)}")
        return str(number)
    if verb == "v" and kind == "null":
        return "null"
    if kind in ("tuple", "set", "object"):
        raise Fail("function.format_collection", f"%{verb} of a {kind}")
    return as_string(value)


# --- CIDR functions ------------------------------------------------------------------------------

_CIDR: Final = re.compile(r"([^/%]+)/(0|[1-9][0-9]{0,2})")


def _network(prefix: Value) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    text = as_string(prefix)
    match = _CIDR.fullmatch(text)
    if match is None or (":" in match.group(1) and "." in match.group(1)):
        raise Fail("function.cidr", f"{text[:40]!r} is not a CIDR prefix DAIL reads")
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError as error:
        raise Fail("function.cidr", str(error)) from error


def _address(network: ipaddress.IPv4Network | ipaddress.IPv6Network, number: int) -> str:
    address: ipaddress.IPv4Address | ipaddress.IPv6Address
    if isinstance(network, ipaddress.IPv4Network):
        address = ipaddress.IPv4Address(number)
    else:
        address = ipaddress.IPv6Address(number)
        if address.ipv4_mapped is not None or (number >> 32) == 0xFFFF:
            raise Fail("function.cidr", "IPv4-mapped IPv6 addresses are not modelled")
    return str(address)


def _cidrsubnet(args: Sequence[Value]) -> Value:
    prefix, newbits_arg, netnum_arg = args
    problem = scalar_problem(prefix, newbits_arg, netnum_arg)
    if problem is not None:
        return problem
    network = _network(prefix)
    newbits, netnum = as_int(newbits_arg), as_int(netnum_arg)
    new_length = network.prefixlen + newbits
    if newbits < 0 or new_length > network.max_prefixlen:
        raise Fail("function.cidr", "insufficient address space to extend the prefix")
    if netnum < 0 or netnum >= 1 << newbits:
        raise Fail("function.cidr", "the network number does not fit in the new bits")
    base = int(network.network_address) + (netnum << (network.max_prefixlen - new_length))
    return Known(f"{_address(network, base)}/{new_length}")


def _cidrhost(args: Sequence[Value]) -> Value:
    prefix, host_arg = args
    problem = scalar_problem(prefix, host_arg)
    if problem is not None:
        return problem
    network = _network(prefix)
    hostnum = as_int(host_arg)
    size = 1 << (network.max_prefixlen - network.prefixlen)
    if not -size <= hostnum < size:
        raise Fail("function.cidr", "the prefix does not accommodate that host number")
    return Known(_address(network, int(network.network_address) + hostnum % size))


# --- The table -----------------------------------------------------------------------------------

# name -> (minimum arguments, maximum arguments or None, implementation)
FUNCTIONS: Final[dict[str, tuple[int, int | None, Function]]] = {
    "toset": (1, 1, _toset),
    "tolist": (1, 1, _tolist),
    "tomap": (1, 1, _tomap),
    "tostring": (1, 1, _tostring),
    "tonumber": (1, 1, _tonumber),
    "tobool": (1, 1, _tobool),
    "concat": (1, None, _concat),
    "merge": (0, None, _merge),
    "length": (1, 1, _length),
    "element": (2, 2, _element),
    "lookup": (2, 3, _lookup),
    "contains": (2, 2, _contains),
    "distinct": (1, 1, _distinct),
    "flatten": (1, 1, _flatten),
    "keys": (1, 1, _keys),
    "values": (1, 1, _values),
    "coalesce": (1, None, _coalesce),
    "compact": (1, 1, _compact),
    "lower": (1, 1, _case(False)),
    "upper": (1, 1, _case(True)),
    "join": (2, None, _join),
    "split": (2, 2, _split),
    "format": (1, None, _format),
    "cidrsubnet": (3, 3, _cidrsubnet),
    "cidrhost": (2, 2, _cidrhost),
}


def call_function(name: str, args: Sequence[Value]) -> Value:
    """Call a function of the subset. ``name`` must be in ``FUNCTIONS``."""
    minimum, maximum, implementation = FUNCTIONS[name]
    if len(args) < minimum or (maximum is not None and len(args) > maximum):
        raise Fail("function.arguments", f"{name}() takes {minimum} to {maximum} arguments")
    return implementation(args)


__all__ = ["FUNCTIONS", "FUNCTION_REASONS", "call_function"]
