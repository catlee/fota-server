#!/usr/bin/env python
import os
import asyncio
import json

import aiohttp
import aiohttp.web
import boto3

import logging

log = logging.getLogger(__name__)


PORT = int(os.environ.get('PORT', 8080))
AWS_BUCKET = os.environ['AWS_BUCKET']
WHITELIST_NAME = os.environ['WHITELIST_NAME']
WHITELIST_REFRESH = int(os.environ.get('WHITELIST_REFRESH', 300))
URL_EXPIRY_TIME = int(os.environ.get('URL_EXPIRY_TIME', 86400))


def make_object_url(bucket_name, object_name, request_method, expires_in,
                    api_kwargs={}):
    """
    Returns a signed URL to the given object

    Arguments:
        bucket_name (str): which bucket to access
        object_name (str): which object to access
        request_method (str): HTTP method to grant permission to. Defaults to
                              'GET'; other values could be 'HEAD'
        expires_in (int): seconds the URL should be valid for
        api_kwargs (dict): additional parameters to pass as arguments to the S3
                           API, e.g. ContentLength
    """
    if request_method in ('GET', 'HEAD'):
        api_method = 'get_object'
    elif request_method in ('PUT', 'POST'):
        api_method = 'put_object'
    else:
        raise ValueError("Unsupported request_method: %s" % request_method)

    api_args = {
        'Bucket': bucket_name,
        'Key': object_name,
    }
    api_args.update(api_kwargs)

    s3 = boto3.client('s3')
    url = s3.generate_presigned_url(
        api_method,
        api_args,
        ExpiresIn=expires_in,
        HttpMethod=request_method,
    )
    return url


class Server:
    """
    Web frontend for serving FOTA updates
    Does IMEI whitelist authentication
    """
    expiry_time = URL_EXPIRY_TIME
    whitelist_refresh_period = WHITELIST_REFRESH
    loop = asyncio.get_event_loop()

    def __init__(self, bucket_name, whitelist_object_name):
        self.bucket_name = bucket_name
        self.whitelist_object_name = whitelist_object_name

        self.imei_whitelist = set()

        log.debug("Using expiry time: %i", self.expiry_time)

    async def load_whitelist(self):
        log.info('loading whitelist...')
        try:
            url = make_object_url(self.bucket_name, self.whitelist_object_name, 'GET', 30)
            log.debug('fetching %s', url)
            resp = await aiohttp.get(url)
            log.debug('getting json')
            data = await resp.json()
            self.imei_whitelist = set(w['imei'] for w in data['whitelist'])
            log.info('got %i entries', len(self.imei_whitelist))
        except:
            log.exception('problem parsing whitelist')
        finally:
            log.info('refreshing whitelist in %i seconds', self.whitelist_refresh_period)
            self.loop.call_later(self.whitelist_refresh_period,
                                 self.loop.create_task, self.load_whitelist())


    async def handle_request(self, request):
        """
        Request handling entry point. This will call each function in
        self.request_processors. If a function returns a truish value, then
        that will be return to the client and processing will stop.

        Arguments:
            request (aiohttp.web.Request object): the client request

        Returns:
            an aiohttp.web.Response object
        """
        log.info('%s %s', request.method, request.path_qs)

        # Check that the IMEI is in our whitelist
        if not 'imei' in request.GET:
            log.info('HTTP 403 %s %s', request.method, request.path_qs)
            return aiohttp.web.Response(status=403, text='Forbidden')

        if request.GET['imei'] not in self.imei_whitelist:
            log.info('HTTP 401 %s %s', request.method, request.path_qs)
            return aiohttp.web.Response(status=401, text='Unauthorized')

        # Make sure they can't access the whitelist itself!
        # TODO: Normalize this?
        object_name = request.path.lstrip('/')
        if object_name == self.whitelist_object_name:
            return aiohttp.web.Response(status=403, text='Forbidden')

        log.debug('generating signed url to %s', object_name)
        assert request.method in ('GET', 'HEAD')
        url = make_object_url(self.bucket_name, object_name, request.method,
                              self.expiry_time)
        log.info('HTTP 302 %s %s %s', request.method, request.path_qs, url)
        return aiohttp.web.HTTPFound(url)


def make_app(server):
    app = aiohttp.web.Application()
    app.router.add_route('get', '/{path:.*}', server.handle_request)
    app.router.add_route('head', '/{path:.*}', server.handle_request)
    return app


if __name__ == '__main__':
    logging.getLogger('botocore').setLevel(logging.WARN)
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s')

    loop = asyncio.get_event_loop()

    s = Server(AWS_BUCKET, WHITELIST_NAME)
    # Load the whitelist
    loop.run_until_complete(s.load_whitelist())

    app = make_app(s)
    handler = app.make_handler()

    server = loop.run_until_complete(
        loop.create_server(handler, '0.0.0.0', PORT))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(handler.finish_connections(1.0))
        server.close()
        loop.run_until_complete(server.wait_closed())
        loop.run_until_complete(app.finish())
    loop.close()
