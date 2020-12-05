# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2020 Johannes Holland
# All rights reserved.

"""Utility functions."""

from functools import wraps


def cached(function):
    """
    Return a wrapper function which caches the return value.
    Caches via the function name. If arguments are present, a setter call
    is assumed and the cache is emtied for that function.
    """

    @wraps(function)
    def wrapped(self, *args, force=False, **kwargs):
        """Wrapper function: cache return value."""
        # add cache to self if does not exist
        if not hasattr(self, "cache"):
            self.cache = {}

        key = function.__name__

        # if function is a getter (no arguments)
        if not args:
            # if already cached, load from cache (suppress with force=True)
            if not force and key in self.cache:
                return self.cache[key]

            # call function and save result to cache
            value = function(self, *args, **kwargs)
            self.cache[key] = value

            return value

        # function is a setter
        # delete cached entry (next call of getter will run)
        if key in self.cache:
            del self.cache[key]

        # call setter
        return function(self, *args, **kwargs)

    return wrapped


def cached_getter_with_args(function):
    """
    Return a wrapper function which caches the return value.
    Caches not only for the function name, but also for its arguments.
    Only works on getters, not on setters.
    """

    @wraps(function)
    def wrapped(self, *args, force=False, **kwargs):
        """Wrapper function: cache return value."""
        # add cache to self if does not exist
        if not hasattr(self, "cache"):
            self.cache = {}

        key = (function.__name__,) + args

        # if already cached, load from cache (suppress with force=True)
        if not force and key in self.cache:
            return self.cache[key]

        # call function and save result to cache
        value = function(self, *args, **kwargs)
        self.cache[key] = value

        return value

    return wrapped
