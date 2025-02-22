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
from swift3.etree import Element, tostring, fromstring, XMLSyntaxError, \
    DocumentInvalid, SubElement
from swift3.iam import check_iam_access
from swift3.response import HTTPOk, NoSuchBucket, MalformedXML
from swift3.utils import LOGGER, VERSIONING_SUFFIX, convert_response, \
    log_s3api_command

MAX_PUT_VERSIONING_BODY_SIZE = 10240


class VersioningController(Controller):
    """
    Handles the following APIs:

     - GET Bucket versioning
     - PUT Bucket versioning

    Those APIs are logged as VERSIONING operations in the S3 server log.
    """
    @public
    @bucket_operation
    @check_iam_access('s3:GetBucketVersioning')
    def GET(self, req):
        """
        Handles GET Bucket versioning.
        """
        log_s3api_command(req, 'get-bucket-versioning')
        info = req.get_container_info(self.app)
        status = None
        versions_container = info.get('sysmeta', {}).get('versions-location')

        if versions_container:
            status = 'Enabled'
        else:
            versions_container = ''.join([req.container_name,
                                          VERSIONING_SUFFIX])
            try:
                req.get_response(
                    self.app, 'HEAD', container=versions_container)
                status = 'Suspended'
            except NoSuchBucket:
                pass

        # Just report there is no versioning configured here.
        elem = Element('VersioningConfiguration')
        if status:
            SubElement(elem, 'Status').text = status
        body = tostring(elem)

        return HTTPOk(body=body, content_type="text/plain")

    @public
    @bucket_operation
    @check_iam_access('s3:PutBucketVersioning')
    def PUT(self, req):
        """
        Handles PUT Bucket versioning.
        """
        log_s3api_command(req, 'put-bucket-versioning')
        xml = req.xml(MAX_PUT_VERSIONING_BODY_SIZE)
        try:
            elem = fromstring(xml, 'VersioningConfiguration')
            status = elem.find('./Status').text
        except (XMLSyntaxError, DocumentInvalid):
            raise MalformedXML()
        except Exception as e:
            LOGGER.error(e)
            raise

        if status not in ['Enabled', 'Suspended']:
            raise MalformedXML()

        # Make sure the versions container exists
        req.container_name += VERSIONING_SUFFIX
        try:
            req.get_container_info(self.app)
        except NoSuchBucket:
            req.get_response(self.app, 'PUT', req.container_name, '')

        # Set up versioning
        if status == 'Enabled':
            req.headers['X-History-Location'] = req.container_name
        else:
            req.headers['X-Remove-History-Location'] = 'true'
        # Set the container back to what it originally was
        req.container_name = req.container_name[:-len(VERSIONING_SUFFIX)]
        resp = req.get_response(self.app, 'POST')

        return convert_response(req, resp, 204, HTTPOk)
