from enum import Enum
from typing import Union


# TODO: Once we've upgraded to python 3.11 we can use StrEnum, so that the value
# is auto computed
class Tag(Enum):
    # Indicates that a test doesn't need to be run on every patchset in CV, so
    # it may get left for a post-commit job
    LowUrgency = "LowUrgency"


def tag_from_str(tag_str: str) -> Union[Tag, str]:
    """
    Convert a tag string into the Tag enum. If the string doesn't match a tag,
    the original string will be returned, for separate error handling

    :param tag_str: A string which may or may not match an instance of Tag
    :return: Either the Tag enum, or the original string
    """
    tag_enum = Tag(tag_str)
    if tag_enum is None:
        raise ValueError(f"{tag_str} is not a tag")
    return tag_enum


def tag(tag_enum: Tag):
    """
    Use @tag(Tag) to give a test a tag.
    They can then be filtered via '--with-tags' or '--without-tags'
    """
    if not isinstance(tag_enum, Tag):
        raise ValueError(f"{tag_enum} is not a Tag")

    def f(t):
        if hasattr(t, "_tags"):
            t._tags.append(tag_enum)
        else:
            t._tags = [tag_enum]
        return t
    return f


def get_tags(test_func):
    return getattr(test_func, "_tags", [])
