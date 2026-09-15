

from __future__ import absolute_import

import itertools

from pex.dist_metadata import Distribution, is_wheel
from pex.orderedset import OrderedSet
from pex.rank import Rank
from pex.third_party.packaging.tags import Tag, parse_tag
from pex.typing import TYPE_CHECKING, cast, overload
from pex.wheel import WHEEL, parse_tags_from_filename

if TYPE_CHECKING:
    from typing import (
        Iterable,
        Iterator,
        List,
        Mapping,
        MutableMapping,
        Optional,
        Text,
        Tuple,
        Union,
    )

    import attr
else:
    from pex.third_party import attr


def _prepare_tags(tags):
    # type: (Iterable[Tag]) -> Tuple[Tag, ...]
    return tags if isinstance(tags, tuple) else tuple(OrderedSet(tags))


class TagRank(Rank["TagRank"]):


@attr.s(frozen=True)
class RankedTag(object):
    tag = attr.ib(order=False)
    rank = attr.ib()

    def select_higher_rank(self, other):
        # type: (Optional[RankedTag]) -> RankedTag
        if other is None:
            return self
        return Rank.select_highest_rank(
            self, other, extract_rank=lambda ranked_tag: ranked_tag.rank
        )


@attr.s(frozen=True)
class CompatibilityTags(object):

    @classmethod
    def from_wheel(
        cls,
        wheel,
        platform_tag=None,
    ):
        # type: (...) -> CompatibilityTags

        if isinstance(wheel, Distribution):
            if not is_wheel(wheel.location):
                return cls(tags=WHEEL.from_distribution(wheel, platform_tag=platform_tag).tags)
            wheel_file_name = wheel.location
        else:
            wheel_file_name = wheel

        return cls(tags=parse_tags_from_filename(wheel_file_name))

    @classmethod
    def from_strings(cls, tags):
        # type: (Iterable[str]) -> CompatibilityTags
        return cls(tags=tuple(itertools.chain.from_iterable(parse_tag(tag) for tag in tags)))

    _tags = attr.ib(converter=_prepare_tags)
    _rankings = attr.ib(eq=False, factory=dict)

    @_tags.validator
    def _validate_tags(
        self,
        attribute,
        value,
    ):
        if not value:
            raise ValueError(
                "The {name} parameter should contain at least one tag; given an empty set.".format(
                    name=attribute.name
                )
            )

    def extend(self, tags):
        # type: (Iterable[Tag]) -> CompatibilityTags
        return CompatibilityTags(self._tags + tuple(tags))

    def compatible_tags(self, tags):
        # type: (Iterable[Tag]) -> OrderedSet[Tag]

        query = frozenset(tags)

        def iter_compatible():
            for tag in self:
                if tag in query:
                    yield tag

        return OrderedSet(iter_compatible())

    def to_string_list(self):
        # type: () -> List[str]
        return [str(tag) for tag in self._tags]

    @property
    def __rankings(self):
        # type: () -> Mapping[Tag, TagRank]
        if not self._rankings:
            self._rankings.update(TagRank.ranked(self._tags))
        return self._rankings

    @property
    def lowest_rank(self):
        # type: () -> TagRank
        return cast(TagRank, self.rank(self[-1]))

    def rank(self, tag):
        # type: (Tag) -> Optional[TagRank]
        return self.__rankings.get(tag)

    def best_match(self, tags):
        # type: (Iterable[Tag]) -> Optional[RankedTag]
        best_match = None
        for tag in tags:
            rank = self.rank(tag)
            if rank is None:
                continue
            ranked_tag = RankedTag(tag=tag, rank=rank)
            if best_match is None or ranked_tag is best_match.select_higher_rank(ranked_tag):
                best_match = ranked_tag
        return best_match

    def __iter__(self):
        # type: () -> Iterator[Tag]
        return iter(self._tags)

    def __len__(self):
        # type: () -> int
        return len(self._tags)

    @overload
    def __getitem__(self, index):
        # type: (int) -> Tag
        pass


    @overload
    def __getitem__(self, slice_):
        # type: (slice) -> CompatibilityTags
        pass

    @overload
    def __getitem__(self, tag):
        # type: (Tag) -> TagRank
        pass

    def __getitem__(self, index_or_slice_or_tag):
        # type: (Union[int, slice, Tag]) -> Union[Tag, CompatibilityTags, TagRank]
        if isinstance(index_or_slice_or_tag, Tag):
            return self.__rankings[index_or_slice_or_tag]
        elif isinstance(index_or_slice_or_tag, slice):
            tags = self._tags[index_or_slice_or_tag]
            return CompatibilityTags(
                tags=tags, rankings={tag: self.__rankings[tag] for tag in tags}
            )
        else:
            return self._tags[index_or_slice_or_tag]
