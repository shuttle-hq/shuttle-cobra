import functools
import inspect
import logging
import os
import typing

from shuttle_common import (
    InfraManifest,
    EcsCronTask,
    EcsCronTaskOptions,
    AllResourcesUnion,
)

logger = logging.getLogger(__name__)


def cron(*args, **kwargs):
    logger.debug(f"decorator called with {args=} {kwargs=}")

    def wrapper(func):
        anno = inspect.get_annotations(func)
        types = typing.get_type_hints(func)
        logger.debug(f"in wrapper {func=} {anno=} {types=}")

        # transform annotations into instances of classes with the args provided
        resources: list[AllResourcesUnion] = []
        for _arg_ident, annotated in anno.items():
            logger.debug(f"{_arg_ident!r} annotations:")
            for meta in annotated.__metadata__:
                logger.debug("-", meta)

            # construct the class in the annotation with the first annotation (options) if there is one
            options = annotated.__metadata__[0] if annotated.__metadata__ else None
            resource = annotated(options=options)
            resources.append(resource)

        infra = InfraManifest(
            service=EcsCronTask(options=EcsCronTaskOptions(**kwargs)),
            resources=resources,
        )

        @functools.wraps(func)
        async def wrapped():
            logger.debug("--- initializing resources ---")
            # replace the "requested" infra manifest with the same manifest populated in the env with the outputs
            infra = InfraManifest.model_validate_json(
                os.environ.get("__SHUTTLE_RUNTIME_INFRA_OUTPUT")
            )
            resources = infra.resources
            # initialize each main function resource and pass them in
            for arg in resources:
                arg.init()
            logger.debug("--- before main executes ---")
            result = await func(*resources)
            logger.debug("--- after main executes ---")
            return result

        wrapped.__shuttle_infra__ = infra

        return wrapped

    return wrapper
