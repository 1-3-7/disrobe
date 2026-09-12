

from contextlib import contextmanager
from typing import Optional

from .core import (
    ParserElement,
    ParseException,
    Keyword,
    __diag__,
    __compat__,
)


class pyparsing_test:

    class reset_pyparsing_context:

        def __init__(self):
            self._save_context = {}

        def save(self):
            self._save_context["default_whitespace"] = ParserElement.DEFAULT_WHITE_CHARS
            self._save_context["default_keyword_chars"] = Keyword.DEFAULT_KEYWORD_CHARS

            self._save_context[
                "literal_string_class"
            ] = ParserElement._literalStringClass

            self._save_context["verbose_stacktrace"] = ParserElement.verbose_stacktrace

            self._save_context["packrat_enabled"] = ParserElement._packratEnabled
            if ParserElement._packratEnabled:
                self._save_context[
                    "packrat_cache_size"
                ] = ParserElement.packrat_cache.size
            else:
                self._save_context["packrat_cache_size"] = None
            self._save_context["packrat_parse"] = ParserElement._parse
            self._save_context[
                "recursion_enabled"
            ] = ParserElement._left_recursion_enabled

            self._save_context["__diag__"] = {
                name: getattr(__diag__, name) for name in __diag__._all_names
            }

            self._save_context["__compat__"] = {
                "collect_all_And_tokens": __compat__.collect_all_And_tokens
            }

            return self

        def restore(self):

            if (
                ParserElement.DEFAULT_WHITE_CHARS
                != self._save_context["default_whitespace"]
            ):
                ParserElement.set_default_whitespace_chars(
                    self._save_context["default_whitespace"]
                )

            ParserElement.verbose_stacktrace = self._save_context["verbose_stacktrace"]

            Keyword.DEFAULT_KEYWORD_CHARS = self._save_context["default_keyword_chars"]
            ParserElement.inlineLiteralsUsing(
                self._save_context["literal_string_class"]
            )

            for name, value in self._save_context["__diag__"].items():
                (__diag__.enable if value else __diag__.disable)(name)

            ParserElement._packratEnabled = False
            if self._save_context["packrat_enabled"]:
                ParserElement.enable_packrat(self._save_context["packrat_cache_size"])
            else:
                ParserElement._parse = self._save_context["packrat_parse"]
            ParserElement._left_recursion_enabled = self._save_context[
                "recursion_enabled"
            ]

            __compat__.collect_all_And_tokens = self._save_context["__compat__"]

            return self

        def copy(self):
            ret = type(self)()
            ret._save_context.update(self._save_context)
            return ret

        def __enter__(self):
            return self.save()

        def __exit__(self, *args):
            self.restore()

    class TestParseResultsAsserts:

        def assertParseResultsEquals(
            self, result, expected_list=None, expected_dict=None, msg=None
        ):
            if expected_list is not None:
                self.assertEqual(expected_list, result.as_list(), msg=msg)
            if expected_dict is not None:
                self.assertEqual(expected_dict, result.as_dict(), msg=msg)

        def assertParseAndCheckList(
            self, expr, test_string, expected_list, msg=None, verbose=True
        ):
            result = expr.parse_string(test_string, parse_all=True)
            if verbose:
                print(result.dump())
            else:
                print(result.as_list())
            self.assertParseResultsEquals(result, expected_list=expected_list, msg=msg)

        def assertParseAndCheckDict(
            self, expr, test_string, expected_dict, msg=None, verbose=True
        ):
            result = expr.parse_string(test_string, parseAll=True)
            if verbose:
                print(result.dump())
            else:
                print(result.as_list())
            self.assertParseResultsEquals(result, expected_dict=expected_dict, msg=msg)

        def assertRunTestResults(
            self, run_tests_report, expected_parse_results=None, msg=None
        ):
            run_test_success, run_test_results = run_tests_report

            if expected_parse_results is not None:
                merged = [
                    (*rpt, expected)
                    for rpt, expected in zip(run_test_results, expected_parse_results)
                ]
                for test_string, result, expected in merged:


                    fail_msg = next(
                        (exp for exp in expected if isinstance(exp, str)), None
                    )
                    expected_exception = next(
                        (
                            exp
                            for exp in expected
                            if isinstance(exp, type) and issubclass(exp, Exception)
                        ),
                        None,
                    )
                    if expected_exception is not None:
                        with self.assertRaises(
                            expected_exception=expected_exception, msg=fail_msg or msg
                        ):
                            if isinstance(result, Exception):
                                raise result
                    else:
                        expected_list = next(
                            (exp for exp in expected if isinstance(exp, list)), None
                        )
                        expected_dict = next(
                            (exp for exp in expected if isinstance(exp, dict)), None
                        )
                        if (expected_list, expected_dict) != (None, None):
                            self.assertParseResultsEquals(
                                result,
                                expected_list=expected_list,
                                expected_dict=expected_dict,
                                msg=fail_msg or msg,
                            )
                        else:

                            print("no validation for {!r}".format(test_string))


            self.assertTrue(
                run_test_success, msg=msg if msg is not None else "failed runTests"
            )

        @contextmanager
        def assertRaisesParseException(self, exc_type=ParseException, msg=None):
            with self.assertRaises(exc_type, msg=msg):
                yield

    @staticmethod
    def with_line_numbers(
        s: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        expand_tabs: bool = True,
        eol_mark: str = "|",
        mark_spaces: Optional[str] = None,
        mark_control: Optional[str] = None,
    ) -> str:
        if expand_tabs:
            s = s.expandtabs()
        if mark_control is not None:
            if mark_control == "unicode":
                tbl = str.maketrans(
                    {c: u for c, u in zip(range(0, 33), range(0x2400, 0x2433))}
                    | {127: 0x2421}
                )
                eol_mark = ""
            else:
                tbl = str.maketrans(
                    {c: mark_control for c in list(range(0, 32)) + [127]}
                )
            s = s.translate(tbl)
        if mark_spaces is not None and mark_spaces != " ":
            if mark_spaces == "unicode":
                tbl = str.maketrans({9: 0x2409, 32: 0x2423})
                s = s.translate(tbl)
            else:
                s = s.replace(" ", mark_spaces)
        if start_line is None:
            start_line = 1
        if end_line is None:
            end_line = len(s)
        end_line = min(end_line, len(s))
        start_line = min(max(1, start_line), end_line)

        if mark_control != "unicode":
            s_lines = s.splitlines()[start_line - 1 : end_line]
        else:
            s_lines = [line + "␊" for line in s.split("␊")[start_line - 1 : end_line]]
        if not s_lines:
            return ""

        lineno_width = len(str(end_line))
        max_line_len = max(len(line) for line in s_lines)
        lead = " " * (lineno_width + 1)
        if max_line_len >= 99:
            header0 = (
                lead
                + "".join(
                    "{}{}".format(" " * 99, (i + 1) % 100)
                    for i in range(max(max_line_len // 100, 1))
                )
                + "\n"
            )
        else:
            header0 = ""
        header1 = (
            header0
            + lead
            + "".join(
                "         {}".format((i + 1) % 10)
                for i in range(-(-max_line_len // 10))
            )
            + "\n"
        )
        header2 = lead + "1234567890" * (-(-max_line_len // 10)) + "\n"
        return (
            header1
            + header2
            + "\n".join(
                "{:{}d}:{}{}".format(i, lineno_width, line, eol_mark)
                for i, line in enumerate(s_lines, start=start_line)
            )
            + "\n"
        )
