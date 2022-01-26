import keyword
import logging

import jpype


# pylint: disable=no-member, too-few-public-methods
@jpype.JImplementationFor("java.lang.Object")
class _JavaObject:

    def __jclass_init__(self: jpype.JClass):
        try:
            if isinstance(self, jpype.JException):
                # don't process any exceptions
                return
            exposer = jpype.JClass("dc3.pyhidra.plugin.PythonFieldExposer")
            if exposer.class_.isAssignableFrom(self.class_):
                return
            utils = jpype.JClass("dc3.pyhidra.property.PropertyUtils")
            for prop in utils.getProperties(self.class_):
                field = prop.field
                if keyword.iskeyword(field):
                    field += '_'
                if field == "class_":
                    continue
                fget = prop.fget if prop.hasGetter() else None
                fset = prop.fset if prop.hasSetter() else None
                self._customize(field, property(fget, fset))

        # allowing any exception to escape here may cause the jvm to terminate
        # pylint: disable=bare-except
        except:
            logger = logging.getLogger(__name__)
            logger.error("Failed to add property customizations for %s", self, exc_info=1)

    def __repr__(self):
        return str(self)
