# Copyright 2021 99cloud
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from typing import Any, Dict, Optional

from cachetools import TTLCache, cached
from cachetools.keys import hashkey
from fastapi import status
from fastapi.exceptions import HTTPException
from keystoneauth1.exceptions.http import Unauthorized
from keystoneauth1.session import Session

from skyline_apiserver import schemas
from skyline_apiserver.client import utils

# Per-worker process-local caches for keystone identity lookups fired on every
# /api/v1/profile and login flow. Session is the per-worker system session and
# not part of the cache key. get_token_data TTL must stay well under keystone
# token lifetime (3600 s) so revoked tokens aren't served as valid for long.
_TOKEN_DATA_CACHE = TTLCache(maxsize=512, ttl=30)
_USER_CACHE = TTLCache(maxsize=2048, ttl=300)


def list_projects(
    profile: schemas.Profile,
    session: Session,
    global_request_id: str,
    all_projects: bool,
    search_opts: Optional[Dict[str, Any]] = None,
) -> Any:
    try:
        search_opts = search_opts if search_opts else {}
        kc = utils.keystone_client(
            session=session,
            region=profile.region,
            global_request_id=global_request_id,
        )
        if not all_projects:
            search_opts["user"] = profile.user.id
        return kc.projects.list(**search_opts)
    except Unauthorized as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


def revoke_token(
    profile: schemas.Profile,
    session: Session,
    global_request_id: str,
    token: str,
) -> None:
    """Revoke a token.
    :param token: The token to be revoked.
    :type token: str or :class:`keystoneclient.access.AccessInfo`
    """
    try:
        kc = utils.keystone_client(
            session=session,
            region=profile.region,
            global_request_id=global_request_id,
        )
        kwargs = {"token": token}
        kc.tokens.revoke_token(**kwargs)
    except Unauthorized as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e),
        )


@cached(_TOKEN_DATA_CACHE, key=lambda token, region, session: hashkey(token))
def get_token_data(token: str, region: str, session: Session) -> Any:
    kc = utils.keystone_client(session=session, region=region)
    return kc.tokens.get_token_data(token=token)


@cached(_USER_CACHE, key=lambda id, region, session: hashkey(id, region))
def get_user(id: str, region: str, session: Session) -> Any:
    kc = utils.keystone_client(session=session, region=region)
    return kc.users.get(id)
