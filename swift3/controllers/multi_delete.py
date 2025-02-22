# Copyright (c) 2010-2014 OpenStack Foundation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from swift.common.utils import public

from swift3.controllers.base import Controller, bucket_operation
from swift3.etree import Element, SubElement, fromstring, tostring, \
    XMLSyntaxError, DocumentInvalid
from swift3.iam import check_iam_access
from swift3.response import HTTPOk, S3NotImplemented, \
    ErrorResponse, MalformedXML, UserKeyMustBeSpecified, AccessDenied, \
    MissingRequestBodyError
from swift3.cfg import CONF
from swift3.utils import LOGGER, log_s3api_command

# 1000 keys with len 1024 and XML overhead
MAX_MULTI_DELETE_BODY_SIZE = 1536000


class MultiObjectDeleteController(Controller):
    """
    Handles Delete Multiple Objects, which is logged as a MULTI_OBJECT_DELETE
    operation in the S3 server log.
    """
    def _gen_error_body(self, error, elem, delete_list):
        for key, version in delete_list:
            if version is not None:
                # TODO: delete the specific version of the object
                raise S3NotImplemented()

            error_elem = SubElement(elem, 'Error')
            SubElement(error_elem, 'Key').text = key
            SubElement(error_elem, 'Code').text = error.__class__.__name__
            SubElement(error_elem, 'Message').text = error._msg

        return tostring(elem)

    @public
    @bucket_operation
    @check_iam_access('s3:DeleteObject')
    def POST(self, req):
        """
        Handles Delete Multiple Objects.
        """
        log_s3api_command(req, 'delete-objects')

        def object_key_iter(elem):
            for obj in elem.iterchildren('Object'):
                key = obj.find('./Key').text
                if not key:
                    raise UserKeyMustBeSpecified()
                version = obj.find('./VersionId')
                if version is not None:
                    version = version.text

                yield key, version

        try:
            xml = req.xml(MAX_MULTI_DELETE_BODY_SIZE)
            if not xml:
                raise MissingRequestBodyError()

            req.check_md5(xml)
            elem = fromstring(xml, 'Delete')

            quiet = elem.find('./Quiet')
            self.quiet = quiet is not None and quiet.text.lower() == 'true'

            delete_list = list(object_key_iter(elem))
            if len(delete_list) > CONF.max_multi_delete_objects:
                raise MalformedXML()
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except ErrorResponse:
            raise
        except Exception as e:
            LOGGER.error(e)
            raise

        elem = Element('DeleteResult')

        # check bucket existence
        try:
            req.get_response(self.app, 'HEAD')
        except AccessDenied as error:
            body = self._gen_error_body(error, elem, delete_list)
            return HTTPOk(body=body)

        for key, version in delete_list:
            if version is not None:
                # TODO: delete the specific version of the object
                raise S3NotImplemented()

            req.object_name = key

            try:
                query = req.gen_multipart_manifest_delete_query(self.app)
                req.get_response(self.app, method='DELETE', query=query)
            except ErrorResponse as e:
                error = SubElement(elem, 'Error')
                SubElement(error, 'Key').text = key
                SubElement(error, 'Code').text = e.__class__.__name__
                SubElement(error, 'Message').text = e._msg
                continue

            if not self.quiet:
                deleted = SubElement(elem, 'Deleted')
                SubElement(deleted, 'Key').text = key

        body = tostring(elem)

        return HTTPOk(body=body)
