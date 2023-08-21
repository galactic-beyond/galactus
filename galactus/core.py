import random as random
import datetime as datetime
import sqlalchemy.dialects.postgresql as pgsql
import sqlalchemy.dialects.sqlite as sqlite
import sqlalchemy as sql
from sqlalchemy import exc
from sqlalchemy.pool import StaticPool
import unittest
import hypothesis as hyp
from hypothesis.provisional import domains, urls
from hypothesis import given
from hypothesis.stateful import Verbosity, Bundle, RuleBasedStateMachine, consumes, multiple, rule, precondition, invariant, initialize
from operator import itemgetter
from argon2 import PasswordHasher
import argon2
import fastapi as fapi
from pydantic import BaseModel, validator
from typing import Any
from uuid import uuid4
import logging
import traceback
import json
from starlette.responses import JSONResponse

g_domains = domains
g_urls = urls


# Print Stack Traces
def print_stack():
    fmt = traceback.format_stack()
    for ln in fmt:
        print(ln.strip())


# Global hasher object
ph = PasswordHasher()


def hash_password(pw):
    return ph.hash(pw)


def verify_password(phash, pw):
    ret = True
    try:
        ret = ph.verify(phash, pw)

    except argon2.exceptions.VerifyMismatchError:
        # Wrong Password
        ret = False

    except argon2.exceptions.InvalidHash:
        # Bad Hash, Probably Data Corruption
        # TODO maybe notify admin
        assert False

    except argon2.exceptions.VerificationError:
        # Other Unspecified Reasons for Failure
        # not sure what to do with this other than return false
        ret = False

    return ret


# Hypothesis Settings
hyp.settings.register_profile("dev", hyp.settings(verbosity=Verbosity.verbose))
hyp.settings.load_profile("dev")
# Unit Test Switch
unit_test_mode = True
# Main Test Switch
galactus_test_mode = True
# Threatslayer Public Key
pub_key = "ceb62cfe-6ad9-4dab-8b34-46fcd6230d8c"
# Initialize Database Tables
db_path_main = "sqlite+pysqlite:///:memory:"
db_path_logs = "sqlite+pysqlite:///:memory:"
if not galactus_test_mode == True:
    # Overwrite test-path with non-test, pg path for main, and sqlite on-disk path for logs.
    assert False
    db_path_main = "sqlite+pysqlite:///:memory:"
    db_path_logs = "sqlite+pysqlite:///:memory:"

connect_args = {"check_same_thread": False}
poolclass = StaticPool
db_engine_main = sql.create_engine(db_path_main,
                                   connect_args=connect_args,
                                   poolclass=poolclass)
db_engine_logs = sql.create_engine(db_path_logs,
                                   connect_args=connect_args,
                                   poolclass=poolclass)
db_metadata_logs = sql.MetaData()
db_metadata_main = sql.MetaData()
# We want to know what failed for which site to (a) help us with diagnosis and
# (b) to allow us to use the error-log as a backlog to update the statistics on
# the stakeable-site object (which can fail if we use concurrent workers).
# If we treat the successful increments as a _sample_, then the error logs
# can help us estimate the deviation of the sample-count from the actual-count
# As a note, if we have `W` workers, the maximum number of drops for a contentious
# update is `W - 1`
log_table = sql.Table("galactus_logs", db_metadata_logs,
                      sql.Column("ctx_event", sql.String),
                      sql.Column("success", sql.Boolean),
                      sql.Column("begin_time", sql.DateTime),
                      sql.Column("end_time", sql.DateTime),
                      sql.Column("error_type", sql.String),
                      sql.Column("site_url", sql.String),
                      sql.Column("error_msg", sql.String))
heatmap_table = sql.Table("galactus_heatmap_logs", db_metadata_logs,
                          sql.Column("write_time", sql.DateTime),
                          sql.Column("src", sql.String),
                          sql.Column("dst", sql.String),
                          sql.Column("heat", sql.Integer))
# If your email is in this table, then it is not confirmed
# If your email is not confirmed after expiration, you stop receiving rewards
email_confirmation_table = sql.Table(
    "email_confirmation", db_metadata_logs, sql.Column("email", sql.String),
    sql.Column("expiration", sql.DateTime),
    sql.Column("confirmation_id", sql.String, primary_key=True))
change_password_confirmation_table = sql.Table(
    "change_password_confirmation", db_metadata_logs,
    sql.Column("username", sql.String), sql.Column("expiration", sql.DateTime),
    sql.Column("confirmation_id", sql.String, primary_key=True))
deleted_galactus_account_table = sql.Table(
    "deleted_account", db_metadata_main,
    sql.Column("username", sql.String, primary_key=True),
    sql.Column("registration_date", sql.DateTime),
    sql.Column("deletion_date", sql.DateTime))
galactus_account_table = sql.Table(
    "galactus_account", db_metadata_main,
    sql.Column("username", sql.String, primary_key=True),
    sql.Column("email", sql.String), sql.Column("salted_password", sql.String),
    sql.Column("api_key", sql.String),
    sql.Column("api_key_expiration", sql.DateTime),
    sql.Column("referred", sql.Integer), sql.Column("referrer", sql.String),
    sql.Column("wallet_id", sql.String),
    sql.Column("wallet_confirmed", sql.Boolean),
    sql.Column("tokens_deposited", sql.Integer),
    sql.Column("tokens_deducted", sql.Integer),
    sql.Column("tokens_deposited_total", sql.Integer),
    sql.Column("tokens_deducted_total", sql.Integer),
    sql.Column("tokens_earned", sql.Integer),
    sql.Column("tokens_earned_total", sql.Integer),
    sql.Column("lookups_total",
               sql.Integer), sql.Column("lookups", sql.Integer),
    sql.Column("malicious_total", sql.Integer),
    sql.Column("malicious", sql.Integer),
    sql.Column("unique_total", sql.Integer), sql.Column("unique", sql.Integer),
    sql.Column("flags_total", sql.Integer), sql.Column("flags", sql.Integer),
    sql.Column("flags_confirmed", sql.Integer),
    sql.Column("unlocks_total", sql.Integer),
    sql.Column("unlocks", sql.Integer),
    sql.Column("unlocks_confirmed", sql.Integer),
    sql.Column("registration_date", sql.DateTime),
    sql.Column("last_request", sql.DateTime))
ilock_policy_table = sql.Table("ilock_policy", db_metadata_main,
                               sql.Column("user_fee", sql.Integer),
                               sql.Column("lookup_fee", sql.Integer),
                               sql.Column("stake_yield", sql.Integer),
                               sql.Column("max_stake", sql.Integer))
site_table = sql.Table("stakeable_site", db_metadata_main,
                       sql.Column("visits", sql.Integer),
                       sql.Column("unlocks", sql.Integer),
                       sql.Column("flags", sql.Integer),
                       sql.Column("url", sql.String, primary_key=True),
                       sql.Column("stake_state", sql.String))
user_allow_block_table = sql.Table(
    "allow_block", db_metadata_main, sql.Column("username", sql.String),
    sql.Column("registration_date", sql.DateTime),
    sql.Column("insert_time", sql.DateTime), sql.Column("url", sql.String),
    sql.Column("block", sql.Boolean))
# This table is used to track time-series fxr anonymously
anon_allow_block_table = sql.Table("anon_allow_block", db_metadata_main,
                                   sql.Column("insert_time", sql.DateTime),
                                   sql.Column("url", sql.String),
                                   sql.Column("block", sql.Boolean))


# Auxiliary Test Switches
# Fuzzer Class
class fuzzer(RuleBasedStateMachine):
    exo = None
    endo = None
    emails = Bundle("emails")
    usernames = Bundle("usernames")
    keys = Bundle("keys")
    passwords = Bundle("passwords")
    urls = Bundle("urls")
    tested_urls = Bundle("tested_urls")
    domains = Bundle("domains")
    # Tuple of username,email,password,key
    credentials = Bundle("credentials")

    @initialize(target=passwords)
    def init_static(self):
        self.exo = exo
        self.endo = endo
        self.endo.reset_machine()
        self.endo.send("ignite")
        assert galactus_test_mode == True
        db_metadata_main.drop_all(db_engine_main)
        db_metadata_logs.drop_all(db_engine_logs)
        db_metadata_main.create_all(db_engine_main)
        db_metadata_logs.create_all(db_engine_logs)
        return "password123"

    @rule(target=emails, email=hyp.strategies.emails())
    def add_email(self, email):
        return email

    @rule(target=keys, key=hyp.strategies.uuids())
    def add_key(self, key):
        return key

    @rule(target=usernames,
          username=hyp.strategies.from_regex(regex='[A-Za-z0-9]+',
                                             fullmatch=True))
    def add_username(self, username):
        return username

    @rule(target=urls, url=g_urls())
    def add_url(self, url):
        return url

    @rule(target=domains, domain=g_domains())
    def add_domain(self, domain):
        return domain

    @rule(target=credentials,
          email=consumes(emails),
          username=consumes(usernames),
          password=passwords)
    def mk_acct(self, email, username, password):
        exo = self.exo
        endo = self.endo
        exo.galactus_account_create(username=username,
                                    unsalted_password=password,
                                    email=email,
                                    api_key=pub_key)
        endo.send("public-galactus-account-create")
        rsp_ls = endo.stackset.stacks["response"]
        rsp = rsp_ls[0]
        if rsp.status == 201:
            new_key = dict_get(rsp.body, "key")
            return (username, email, password, new_key)
        elif rsp.status == 409:
            tmp = 1
            return None
        else:
            assert False

    @rule(credential=credentials, email=emails, password=passwords)
    def mk_old_acct(self, credential, email, password):
        exo = self.exo
        endo = self.endo
        c = credential
        if c == None:
            return

        username = c[0]
        exo.galactus_account_create(username=username,
                                    unsalted_password=password,
                                    email=email,
                                    api_key=pub_key)
        endo.send("public-galactus-account-create")
        rsp_ls = endo.stackset.stacks["response"]
        rsp = rsp_ls[0]
        if rsp.status == 201:
            assert False
        elif rsp.status == 409:
            assert True
        else:
            assert False

    @rule(username=usernames, password=passwords)
    def rm_new_acct(self, username, password):
        exo = self.exo
        endo = self.endo
        exo.galactus_account_create(username=username,
                                    unsalted_password=password,
                                    api_key=pub_key)
        endo.send("public-galactus-account-destroy")

    @rule(credential=consumes(credentials))
    def rm_old_acct(self, credential):
        exo = self.exo
        endo = self.endo
        c = credential
        if c == None:
            return

        username = c[0]
        password = c[2]
        exo.galactus_account_create(username=username,
                                    unsalted_password=password,
                                    api_key=pub_key)
        endo.send("public-galactus-account-destroy")

    @rule(credential=credentials)
    def login_old_acct(self, credential):
        exo = self.exo
        endo = self.endo
        c = credential
        if c == None:
            return

        username = c[0]
        password = c[2]
        exo.galactus_account_create(username=username,
                                    api_key=pub_key,
                                    unsalted_password=password)
        endo.send("public-galactus-account-login")

    @rule(credential=credentials)
    def login_old_acct_bad_pw(self, credential):
        exo = self.exo
        endo = self.endo
        c = credential
        if c == None:
            return

        username = c[0]
        # Intentionally incorrect
        password = c[1]
        exo.galactus_account_create(username=username,
                                    api_key=pub_key,
                                    unsalted_password=password)
        endo.send("public-galactus-account-login")

    @rule(username=usernames, password=passwords)
    def login_new_acct(self, username, password):
        exo = self.exo
        endo = self.endo
        exo.galactus_account_create(username=username,
                                    api_key=pub_key,
                                    unsalted_password=password)
        endo.send("public-galactus-account-login")

    @rule(username=usernames, bkey=keys)
    def logout_new_acct(self, username, bkey):
        key = str(bkey)
        exo = self.exo
        endo = self.endo
        exo.galactus_account_create(username=username,
                                    api_key=key,
                                    unsalted_password='placeholder')
        endo.send("public-galactus-account-logout")

    @rule(credential=credentials)
    def logout_old_acct(self, credential):
        exo = self.exo
        endo = self.endo
        c = credential
        if c == None:
            return

        username = c[0]
        key = c[3]
        exo.galactus_account_create(username=username,
                                    api_key=key,
                                    salted_password='placeholder')
        endo.send("public-galactus-account-logout")

    @rule(target=tested_urls, url=urls, credential=credentials)
    def test_site_calm(self, url, credential):
        exo = self.exo
        endo = self.endo
        c = credential
        if c == None:
            return None

        username = c[0]
        key = c[3]
        exo.galactus_account_create(username=username,
                                    api_key=key,
                                    salted_password='placeholder')
        exo.site_create(url=url)
        exo.stochasticity_create(octa=True)
        endo.send("public-site-safe")
        exo.stackset.pop_unsafe("stochasticity")
        rsp_ls = endo.stackset.stacks["response"]
        rsp = rsp_ls[0]
        if rsp.status == 200:
            assert True
        else:
            assert False

        return url

    @rule(target=tested_urls, url=urls, credential=credentials)
    def test_site(self, url, credential):
        exo = self.exo
        endo = self.endo
        c = credential
        if c == None:
            return None

        username = c[0]
        key = c[3]
        exo.galactus_account_create(username=username,
                                    api_key=key,
                                    salted_password='placeholder')
        exo.site_create(url=url)
        exo.stochasticity_create(octa=True, retries=True)
        endo.send("public-site-safe")
        exo.stackset.pop_unsafe("stochasticity")
        return url

    @rule(url=tested_urls, credential=credentials)
    def retest_site(self, url, credential):
        if url == None:
            return None

        self.test_site(url, credential)

    @rule(target=tested_urls, url=urls)
    def test_site_anon_calm(self, url):
        exo = self.exo
        endo = self.endo
        exo.galactus_account_create(username='username',
                                    api_key=pub_key,
                                    salted_password='placeholder')
        exo.site_create(url=url)
        exo.stochasticity_create(octa=True)
        endo.send("public-site-safe")
        exo.stackset.pop_unsafe("stochasticity")
        rsp_ls = endo.stackset.stacks["response"]
        rsp = rsp_ls[0]
        if rsp.status == 200:
            assert True
        else:
            assert False

        return url

    @rule(url=tested_urls)
    def retest_site_anon_calm(self, url):
        if url == None:
            return None

        self.test_site_anon_calm(url)

    @rule(target=tested_urls, url=urls)
    def test_site_anon(self, url):
        exo = self.exo
        endo = self.endo
        exo.galactus_account_create(username='username',
                                    api_key=pub_key,
                                    salted_password='placeholder')
        exo.site_create(url=url)
        exo.stochasticity_create(octa=True, retries=True)
        endo.send("public-site-safe")
        exo.stackset.pop_unsafe("stochasticity")
        return url

    @rule(url=tested_urls)
    def retest_site_anon(self, url):
        if url == None:
            return None

        self.test_site_anon(url)


if galactus_test_mode == True:
    db_metadata_main.drop_all(db_engine_main)
    db_metadata_logs.drop_all(db_engine_logs)

db_metadata_main.create_all(db_engine_main)
db_metadata_logs.create_all(db_engine_logs)


# Aux Boolean Funcs for Verification
def response_body_keys(bod):
    keys = []
    for k in bod:
        keys.append(k)

    return keys


def key_response_sane(bod):
    keys = response_body_keys(bod)
    b = True
    b = (b and not bod == None)
    b = (b and len(keys) == 1)
    b = (b and keys[0] == "key")
    b = (b and isinstance(bod["key"], str))
    return b


def pub_key_response_sane(bod):
    b = key_response_sane(bod)
    b = (b and bod["key"] == pub_key)
    return b


def login_response_sane(bod):
    keys = response_body_keys(bod)
    b = True
    b = (b and not bod == None)
    b = (b and len(keys) == 3)
    b = (b and is_member("key", keys))
    b = (b and is_member("username", keys))
    b = (b and is_member("email", keys))
    b = (b and isinstance(bod["key"], str))
    b = (b and isinstance(bod["username"], str))
    b = (b and isinstance(bod["email"], str))
    return b


def malicious_response_sane(bod):
    keys = response_body_keys(bod)
    b = True
    b = (b and not bod == None)
    b = (b and len(keys) == 1)
    b = (b and is_member("malicious", keys))
    # The classification-member on the site-object can accept any kind of data-type
    # Here, however, we tend to assume integration with Octahedron, which only returns bools
    # If Octahedron ever changes what it returns, this test will need to change
    # The combination of a boolean-return and 'UNKNOWN'-string-return, basically means we return a ternary value
    b = (b and
         (isinstance(bod["malicious"], bool) or bod["malicious"] == "unknown"))
    return b


def is_member(elem, ls):
    for i in ls:
        if i == elem:
            return True

    return False


class email_confirmation(object):
    _exo = None
    expiration = datetime.datetime.now()
    confirmation_id = ""
    email = ""

    def __init__(self,
                 _exo,
                 expiration=datetime.datetime.now(),
                 confirmation_id="",
                 email=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.expiration = expiration
        self.confirmation_id = confirmation_id
        self.email = email
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("email-confirmation", self)
        exo.stackset.pop_unsafe("email-confirmation")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class change_password_confirmation(object):
    _exo = None
    expiration = datetime.datetime.now()
    confirmation_id = ""
    username = ""

    def __init__(self,
                 _exo,
                 expiration=datetime.datetime.now(),
                 confirmation_id="",
                 username=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.expiration = expiration
        self.confirmation_id = confirmation_id
        self.username = username
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("change-password-confirmation", self)
        exo.stackset.pop_unsafe("change-password-confirmation")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class paging_control(object):
    _exo = None
    filt = ""
    page_num = 0
    quantity = 0

    def __init__(self, _exo, filt="", page_num=0, quantity=0):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.filt = filt
        self.page_num = page_num
        self.quantity = quantity
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("paging-control", self)
        (exo.page_num_zero_plus().verify())
        (exo.page_quantity_one_plus().verify())
        exo.stackset.pop_unsafe("paging-control")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class context(object):
    _exo = None
    locked = False
    timestamp_end = datetime.datetime.now()
    timestamp_start = datetime.datetime.now()
    event = ""

    def __init__(self,
                 _exo,
                 locked=False,
                 timestamp_end=datetime.datetime.now(),
                 timestamp_start=datetime.datetime.now(),
                 event=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.locked = locked
        self.timestamp_end = timestamp_end
        self.timestamp_start = timestamp_start
        self.event = event
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("context", self)
        (exo.context_is_locked().end_after_start().guarded_verify())
        exo.stackset.pop_unsafe("context")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class stochasticity(object):
    _exo = None
    n_retries = 0
    retries = False
    n_octa = 0
    octa = False
    n_load = 0
    load = False
    n_store = 0
    store = False

    def __init__(self,
                 _exo,
                 n_retries=0,
                 retries=False,
                 n_octa=0,
                 octa=False,
                 n_load=0,
                 load=False,
                 n_store=0,
                 store=False):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.n_retries = n_retries
        self.retries = retries
        self.n_octa = n_octa
        self.octa = octa
        self.n_load = n_load
        self.load = load
        self.n_store = n_store
        self.store = store
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("stochasticity", self)
        (exo.stochasticity_non_zero_truth())
        exo.stackset.pop_unsafe("stochasticity")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class response(object):
    _exo = None
    locked = False
    body = None
    status = 200

    def __init__(self, _exo, locked=False, body=None, status=200):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.locked = locked
        self.body = body
        self.status = status
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("response", self)
        (exo.response_is_locked().valid_response_body().andify().
         guarded_verify())
        (exo.response_is_locked().valid_response_status().andify().
         guarded_verify())
        exo.stackset.pop_unsafe("response")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class backoff_strategy(object):
    _exo = None
    randomness = 0
    retries = 0
    scale_factor = 0
    max_delay_ms = 0
    delay_ms = 0
    min_delay_ms = 0

    def __init__(self,
                 _exo,
                 randomness=0,
                 retries=0,
                 scale_factor=0,
                 max_delay_ms=0,
                 delay_ms=0,
                 min_delay_ms=0):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.randomness = randomness
        self.retries = retries
        self.scale_factor = scale_factor
        self.max_delay_ms = max_delay_ms
        self.delay_ms = delay_ms
        self.min_delay_ms = min_delay_ms
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("backoff-strategy", self)
        (exo.randomness_zero_one().verify())
        (exo.delay_in_range().verify())
        exo.stackset.pop_unsafe("backoff-strategy")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class db_load_query(object):
    _exo = None
    q = None

    def __init__(self, _exo, q=None):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.q = q
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("db-load-query", self)
        (exo.load_query_exists().verify())
        exo.stackset.pop_unsafe("db-load-query")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class db_store_query(object):
    _exo = None
    q = None

    def __init__(self, _exo, q=None):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.q = q
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("db-store-query", self)
        (exo.store_query_exists().verify())
        exo.stackset.pop_unsafe("db-store-query")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class db_error(object):
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("db-error", self)
        exo.stackset.pop_unsafe("db-error")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class blockchain_error(object):
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("blockchain-error", self)
        exo.stackset.pop_unsafe("blockchain-error")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class input_error(object):
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("input-error", self)
        exo.stackset.pop_unsafe("input-error")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class octahedron_error(object):
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("octahedron-error", self)
        exo.stackset.pop_unsafe("octahedron-error")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class ilock_policy(object):
    _exo = None
    max_stake = 0
    stake_yield = 0
    lookup_fee = 0
    user_fee = 0

    def __init__(self,
                 _exo,
                 max_stake=0,
                 stake_yield=0,
                 lookup_fee=0,
                 user_fee=0):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.max_stake = max_stake
        self.stake_yield = stake_yield
        self.lookup_fee = lookup_fee
        self.user_fee = user_fee
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("ilock-policy", self)
        exo.stackset.pop_unsafe("ilock-policy")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class octa_verdict(object):
    _exo = None
    safe = False

    def __init__(self, _exo, safe=False):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.safe = safe
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("octa-verdict", self)
        exo.stackset.pop_unsafe("octa-verdict")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class site(object):
    _exo = None
    url = ""
    flags = 0
    unlocks = 0
    visits = 0
    stake_state = "neutral"
    unique = False
    classification = None

    def __init__(self,
                 _exo,
                 url="",
                 flags=0,
                 unlocks=0,
                 visits=0,
                 stake_state="neutral",
                 unique=False,
                 classification=None):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.url = url
        self.flags = flags
        self.unlocks = unlocks
        self.visits = visits
        self.stake_state = stake_state
        self.unique = unique
        self.classification = classification
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("site", self)
        (exo.stake_state_valid().verify())
        exo.stackset.pop_unsafe("site")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class allow_block_list_item(object):
    _exo = None
    block = False
    url = ""
    user_registration_date = datetime.datetime.now()
    username = ""

    def __init__(self,
                 _exo,
                 block=False,
                 url="",
                 user_registration_date=datetime.datetime.now(),
                 username=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.block = block
        self.url = url
        self.user_registration_date = user_registration_date
        self.username = username
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("allow-block-list-item", self)
        exo.stackset.pop_unsafe("allow-block-list-item")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class deleted_galactus_account(object):
    _exo = None
    deletion_date = datetime.datetime.now()
    registration_date = datetime.datetime.now()
    username = ""

    def __init__(self,
                 _exo,
                 deletion_date=datetime.datetime.now(),
                 registration_date=datetime.datetime.now(),
                 username=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.deletion_date = deletion_date
        self.registration_date = registration_date
        self.username = username
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("deleted-galactus-account", self)
        (exo.regdel_dates_sane().verify())
        (exo.have_username().verify())
        exo.stackset.pop_unsafe("deleted-galactus-account")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class galactus_account(object):
    _exo = None
    locked = False
    api_key_expiration = datetime.datetime.now()
    last_request = datetime.datetime.now()
    api_key = ""
    referrer = ""
    referred = 0
    registration_date = datetime.datetime.now()
    unlocks_confirmed = 0
    flags_confirmed = 0
    unlocks = 0
    unlocks_total = 0
    flags = 0
    flags_total = 0
    unique = 0
    unique_total = 0
    malicious = 0
    malicious_total = 0
    lookups = 0
    lookups_total = 0
    tokens_earned_total = 0
    tokens_earned = 0
    tokens_deducted = 0
    tokens_deposited = 0
    wallet_confirmed = False
    wallet_id = ""
    unsalted_password = ""
    salted_password = ""
    email = ""
    username = ""

    def __init__(self,
                 _exo,
                 locked=False,
                 api_key_expiration=datetime.datetime.now(),
                 last_request=datetime.datetime.now(),
                 api_key="",
                 referrer="",
                 referred=0,
                 registration_date=datetime.datetime.now(),
                 unlocks_confirmed=0,
                 flags_confirmed=0,
                 unlocks=0,
                 unlocks_total=0,
                 flags=0,
                 flags_total=0,
                 unique=0,
                 unique_total=0,
                 malicious=0,
                 malicious_total=0,
                 lookups=0,
                 lookups_total=0,
                 tokens_earned_total=0,
                 tokens_earned=0,
                 tokens_deducted=0,
                 tokens_deposited=0,
                 wallet_confirmed=False,
                 wallet_id="",
                 unsalted_password="",
                 salted_password="",
                 email="",
                 username=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.locked = locked
        self.api_key_expiration = api_key_expiration
        self.last_request = last_request
        self.api_key = api_key
        self.referrer = referrer
        self.referred = referred
        self.registration_date = registration_date
        self.unlocks_confirmed = unlocks_confirmed
        self.flags_confirmed = flags_confirmed
        self.unlocks = unlocks
        self.unlocks_total = unlocks_total
        self.flags = flags
        self.flags_total = flags_total
        self.unique = unique
        self.unique_total = unique_total
        self.malicious = malicious
        self.malicious_total = malicious_total
        self.lookups = lookups
        self.lookups_total = lookups_total
        self.tokens_earned_total = tokens_earned_total
        self.tokens_earned = tokens_earned
        self.tokens_deducted = tokens_deducted
        self.tokens_deposited = tokens_deposited
        self.wallet_confirmed = wallet_confirmed
        self.wallet_id = wallet_id
        self.unsalted_password = unsalted_password
        self.salted_password = salted_password
        self.email = email
        self.username = username
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("galactus-account", self)
        (exo.have_wallet_id().verify())
        (exo.
         galactus_account_is_locked().have_either_salted_or_unsalted_password(
         ).have_api_key().andify().guarded_verify())
        (exo.have_username().verify())
        exo.stackset.pop_unsafe("galactus-account")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class leaderboard(object):
    _exo = None
    dummy = 0

    def __init__(self, _exo, dummy=0):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.dummy = dummy
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("leaderboard", self)
        exo.stackset.pop_unsafe("leaderboard")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class reward_strategy(object):
    _exo = None
    dummy = 0

    def __init__(self, _exo, dummy=0):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.dummy = dummy
        self.__dict__["__constructed"] = True
        self.__assert__()
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        exo.stackset.push_unsafe("reward-strategy", self)
        exo.stackset.pop_unsafe("reward-strategy")
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return


class StackSet:
    stacks = {}
    changeable = []
    readable = []

    def __init__(self):
        stacks = self.stacks
        dict_put(stacks, "prev-state", [])
        dict_put(stacks, "state", [])
        dict_put(stacks, "next-state", [])
        dict_put(stacks, "prev-event", [])
        dict_put(stacks, "event", [])
        dict_put(stacks, "eventset", [])
        dict_put(stacks, "number", [])
        dict_put(stacks, "boolean", [])
        dict_put(stacks, "string", [])
        dict_put(stacks, "datetime", [])
        dict_put(stacks, "galactus-account", [])
        dict_put(stacks, "deleted-galactus-account", [])
        dict_put(stacks, "site", [])
        dict_put(stacks, "leaderboard", [])
        dict_put(stacks, "paging-control", [])
        dict_put(stacks, "context", [])
        dict_put(stacks, "stochasticity", [])
        dict_put(stacks, "db-load-query", [])
        dict_put(stacks, "db-store-query", [])
        dict_put(stacks, "ilock-policy", [])
        dict_put(stacks, "reward-strategy", [])
        dict_put(stacks, "response", [])
        dict_put(stacks, "octa-verdict", [])
        dict_put(stacks, "backoff-strategy", [])
        dict_put(stacks, "db-error", [])
        dict_put(stacks, "blockchain-error", [])
        dict_put(stacks, "octahedron-error", [])
        dict_put(stacks, "input-error", [])

    def set_readable(self, readables):
        self.readable = readables

    def set_changeable(self, changeables):
        self.changeable = changeables

    def reset_access(self):
        self.changeable = []
        self.readable = []

    def push(self, stackname, elem):
        allowed = is_member(stackname, self.changeable)
        assert allowed
        stack = self.stacks[stackname]
        stack.append(elem)
        return elem

    def push_unsafe(self, stackname, elem):
        stack = self.stacks[stackname]
        stack.append(elem)
        return elem

    def pop(self, stackname):
        allowed = is_member(stackname, self.changeable)
        assert allowed
        stack = self.stacks[stackname]
        ret = None
        if len(stack) > 0:
            ret = stack.pop()

        return ret

    def pop_unsafe(self, stackname):
        stack = self.stacks[stackname]
        ret = None
        if len(stack) > 0:
            ret = stack.pop()

        return ret

    def stack_len(self, stackname):
        allowed2 = is_member(stackname, self.readable)
        assert allowed2
        stack = self.stacks[stackname]
        ret = len(stack)
        return ret

    def peek(self, stackname):
        allowed = is_member(stackname, self.readable)
        assert allowed
        stack = self.stacks[stackname]
        slen = len(stack)
        pos = (slen - 1)
        ret = None
        if pos >= 0:
            ret = stack[pos]

        return ret

    def peek_list(self, stackname):
        allowed = is_member(stackname, self.readable)
        assert allowed
        stack = self.stacks[stackname]
        return stack

    def peek_n(self, stackname, pos):
        allowed = is_member(stackname, self.readable)
        assert allowed
        stack = self.stacks[stackname]
        slen = len(stack)
        max_pos = (slen - 1)
        ret = None
        if (pos >= 0 and pos <= max_pos):
            ret = stack[pos]

        return ret


def list_get(l, i):
    assert (i > 0 and i < len(l))
    return l[i]


def dict_to_list(d):
    ret = []
    for k in d:
        ret.append((k, dict_get(d, k)))

    return ret


def dict2_to_list(d):
    ret = []
    for k in d:
        d2 = dict_get(d, k)
        for k2 in d2:
            ret.append((k, k2, dict_get(d2, k2)))

    return ret


def dict_get(d, k):
    assert not k == None
    if d == None:
        return None

    return d.get(k)


def dict_2get(d, k1, k2):
    assert not k1 == None
    assert not k2 == None
    if d == None:
        return None

    d2 = d.get(k1)
    if d2 == None:
        return None

    return d2.get(k2)


def dict_3get(d, k1, k2, k3):
    assert not k1 == None
    assert not k2 == None
    assert not k3 == None
    if d == None:
        return None

    d2 = d.get(k1)
    if d2 == None:
        return None

    d3 = d.get(k2)
    if d3 == None:
        return None

    return d3.get(k3)


def tuple_cat_01(tpl):
    a = tpl[0]
    b = tpl[1]
    return (a + b)


def list_put(l, i, v):
    l[i] = v


def dict_put(d, k, v):
    assert not k == None
    assert not v == None
    if d == None:
        return None

    d[k] = v
    return v


def dict_2put(d, k1, k2, v):
    assert not k1 == None
    assert not k2 == None
    assert not v == None
    if d == None:
        return None

    d2 = d.get(k1)
    if d2 == None:
        d[k1] = {}
        d2 = d.get(k1)

    d2[k2] = v
    return v


def dict_3put(d, k1, k2, k3, v):
    assert not k1 == None
    assert not k2 == None
    assert not k3 == None
    assert not v == None
    if d == None:
        return None

    d2 = d.get(k1)
    if d2 == None:
        d[k1] = {}
        d2 = d.get(k1)

    d3 = d.get(k1)
    if d3 == None:
        d[k2] = {}
        d3 = d.get(k2)

    d3[k3] = v
    return v


def pre_verify():
    if galactus_test_mode == True:
        # backoff-reset
        (exo.state_create(
            name="ready").state_is().backoff_is_reset().guarded_verify())
        # ready-contextualized
        (exo.state_create(name="ready").prev_state_is().context_empty().is_not(
        ).guarded_verify())
        # ready-empty-response
        (exo.state_create(
            name="ready").prev_state_is().response_empty().guarded_verify())
        # loaded-config
        (exo.state_create(name="ready").state_is().ilock_policy_empty().is_not(
        ).guarded_verify())
        # account-regdate-context-matches-try
        (exo.state_create(
            name="galactus-store-tried").next_state_is().context_create(
                event="public-galactus-account-create").context_is().andify().
         account_regdate_after_context_timestamp().guarded_verify())
        # two-accounts-for-logout-try
        (exo.state_create(
            name="galactus-store-tried").next_state_is().context_create(
                event="public-galactus-account-logout").context_is().andify().
         number_create(
             val=2).galactus_account_length().number_gteq().guarded_verify())
        # new-api-key-on-logout
        (exo.state_create(name="ready").next_state_is().state_create(
            name="begin-here").state_is().is_not().andify().context_create(
                event="public-galactus-account-logout").context_is().andify().
         galactus_account_has_new_api_key().andify().guarded_verify())


def post_verify():
    if galactus_test_mode == True:
        # respond-on-ready
        (exo.state_create(name="ready").next_state_is().state_create(
            name="begin-here").state_is().is_not().andify().response_empty().
         is_not().response_is_locked().andify().guarded_verify())
        # galactus-account-last-req
        (exo.state_create(name="ready").prev_state_is().galactus_account_empty(
        ).is_not().andify().galactus_account_has_last_req().guarded_verify())
        # two-queries-safety
        (exo.state_create(name="ready").state_is().state_create(
            name="galactus-load-tried").next_state_is().
         andify().context_create(event="public-site-safe").context_is().andify(
         ).db_load_query_length().number_create(
             val=2).number_eq().guarded_verify())
        # octa-test-empty-load
        (exo.state_create(
            name="test-safety-tried").next_state_is().state_create(
                name="galactus-load-tried").state_is().andify().
         db_load_query_empty().guarded_verify())
        # ready-empty-account
        (exo.state_create(name="ready").next_state_is().galactus_account_empty(
        ).guarded_verify())
        # ready-empty-context
        (exo.state_create(
            name="ready").next_state_is().context_empty().guarded_verify())
        # ready-empty-store
        (exo.state_create(name="ready").next_state_is().db_store_query_empty().
         guarded_verify())
        # ready-empty-load
        (exo.state_create(name="ready").next_state_is().db_load_query_empty().
         guarded_verify())
        # store-query-present-try
        (exo.state_create(name="galactus-store-tried").next_state_is().
         db_store_query_empty().is_not().guarded_verify())
        # load-query-empty-try
        (exo.state_create(name="galactus-store-tried").next_state_is().
         db_load_query_empty().guarded_verify())
        # load-query-present-try
        (exo.state_create(name="galactus-load-tried").next_state_is().
         db_load_query_empty().is_not().guarded_verify())
        # ready-empty-site
        (exo.state_create(
            name="ready").next_state_is().site_empty().guarded_verify())
        # ready-empty-backoff
        (exo.state_create(name="ready").next_state_is().backoff_strategy_empty(
        ).is_not().guarded_verify())


class Endo:
    exo = {}
    wait_states = ["ready", "panic"]
    transitions = {}
    transition_code = {}
    valid_events = {}
    eventsets = {}
    rev_eventsets = {}
    heatmap = {}
    state = "begin-here"
    event = None
    ev_up = 0
    stackset = StackSet()
    ticker = 0
    ticker_max = 0

    def reset_machine(self):
        # We reset everything to the defaults except the durable data like transitions, valid-events, heatmaps, etc
        self.state = "begin-here"
        self.event = None
        self.ev_up = 0
        self.stackset = StackSet()
        self.ticker = 0
        self.ticker_max = 0
        self.stackset.set_changeable(["state"])
        self.stackset.push("state", self.state)
        self.stackset.reset_access()

    def update_event(self, event, eventset):
        self.stackset.set_changeable(["event", "prev-event", "eventset"])
        pe = self.stackset.pop("event")
        if not pe == event:
            # Only store new events as previous events
            # No new informatin gets communicate by storing the same event in both stacks
            # If you need to know whether an event has been called more than once, use a first-class counter
            # The prev-event stack exists to assist with testing and provide certain context-info to verbs
            self.stackset.push("prev-event", pe)

        event_ult = event
        if not event == None:
            self.stackset.push("event", event)

        self.stackset.pop("eventset")
        if not eventset == None:
            self.stackset.push("eventset", eventset)
            event_ult = eventset

        self.stackset.reset_access()
        self.event = event_ult
        if event_ult == None:
            self.ev_up = 0
        else:
            assert not self.ev_up == 1
            self.ev_up = 1

    def valid_event(self):
        assert self.ev_up == 1

    def update_next_state(self, dest):
        self.stackset.set_changeable(["next-state"])
        self.stackset.pop("next-state")
        self.stackset.push("next-state", dest)
        self.stackset.reset_access()

    def heatmap_to_list(self, sort_order="alpha", src=None, dst=None):
        # List of triples (from, to, heat), sorted alphabetically by default
        hm = self.heatmap
        hmls = dict2_to_list(hm)
        # TODO generalize this by asserting xor from/to and having onle 1 filter
        if not src == None:
            hmls2 = []
            for v in hmls:
                if src == v[0]:
                    hmls2.append(v)

            hmls = hmls2

        if not dst == None:
            hmls2 = []
            for v in hmls:
                if dst == v[1]:
                    hmls2.append(v)

            hmls = hmls2

        if sort_order == "alpha":
            hmls = sorted(hmls, key=tuple_cat_01)
        elif sort_order == "hotness":
            hmls = sorted(hmls, key=itemgetter(2), reverse=True)
        elif sort_order == "coldness":
            hmls = sorted(hmls, key=itemgetter(2))

        return hmls

    def print_heatmap(self):
        # TODO make this line-based output (i.e. each entry is a row with 3 cols)
        return print(self.heatmap_to_list())

    def state_outbound_heatmap(self, state, sort_order="alpha"):
        return self.heatmap_to_list(src=state, sort_order=sort_order)

    def state_inbound_heatmap(self, state, sort_order="alpha"):
        return self.heatmap_to_list(dst=state, sort_order=sort_order)

    def update_state(self, dest):
        start = self.state
        event = self.event
        trans_count = dict_2get(self.heatmap, start, dest)
        if trans_count == None:
            trans_count = 1
        else:
            trans_count = (trans_count + 1)

        dict_2put(self.heatmap, start, dest, trans_count)
        self.stackset.set_changeable(["state", "prev-state", "next-state"])
        self.stackset.pop("prev-state")
        self.stackset.push("prev-state", start)
        self.stackset.pop("state")
        self.stackset.push("state", dest)
        self.state = dest
        self.stackset.pop("next-state")
        self.stackset.reset_access()

    def resume(self):
        self.ticker = 0
        self.tick_until_false()

    def send(self, event):
        valid = dict_get(self.valid_events, event)
        assert valid == True
        eventset = None
        eventset_dest = None
        eventsets = dict_get(self.eventsets, event)
        self.ticker = 0
        if not eventsets == None:
            if len(eventsets) == 1:
                eventset = eventsets[0]
            elif len(eventsets) > 1:
                assert False

        dest = dict_2get(self.transitions, self.state, event)
        if not eventset == None:
            eventset_dest = dict_2get(self.transitions, self.state, eventset)

        dest_ult = None
        assert (not (dest and eventset_dest) and (dest or eventset_dest))
        if not dest == None:
            event_ult = event
            dest_ult = dest
        elif not eventset_dest == None:
            event_ult = eventset
            dest_ult = eventset_dest

        self.update_event(event, eventset)
        # Send is special because it can potentially update the event twice in a single tick.
        # ev_up is intended to cause failure if a more than 1 event is emitted by any transition
        # we **really** have not figured out what to do in this case, and are considering some way
        # of specifying event-priorities in the future.
        self.ev_up = 0
        code = dict_2get(self.transition_code, self.state, event_ult)
        self.update_next_state(dest_ult)
        code(self)
        self.update_state(dest_ult)
        self.tick_until_false()

    def tick_until_false(self):
        ret = True
        while ret == True:
            ret = self.tick()
            if self.ticker_max > 0:
                tl = self.ticker <= self.ticker_max
                ret = (ret and tl)

        if (ret == False and self.ticker_max == 0):
            assert self.is_wait_state()

        return ret

    def is_wait_state(self):
        state = self.state
        b = False
        for s in self.wait_states:
            if s == state:
                b = True

        return b

    def get_next_events(self):
        ret = []
        ev_dict = dict_get(self.transitions, self.state)
        for ev_k in ev_dict:
            ret.append(ev_k)

        return ret

    def get_next_states(self):
        evs = self.get_next_events()
        ret = []
        for e in evs:
            ret.append(dict_2get(self.transitions, self.state, e))

        return ret

    def tick(self):
        if self.event == None:
            return False

        self.ev_up = 0
        dest = dict_2get(self.transitions, self.state, self.event)
        dest_always = dict_2get(self.transitions, self.state, "@always")
        eventsets = dict_get(self.eventsets, self.event)
        self.ticker = (self.ticker + 1)
        eventset = None
        if not eventsets == None:
            if len(eventsets) == 1:
                eventset = eventsets[0]
            elif len(eventsets) > 1:
                # TODO handle multiple eventset membership and any ambiguity
                assert False

        assert not (dest and dest_always)
        if (dest == None and dest_always == None):
            eventset_dest = dict_2get(self.transitions, self.state, eventset)

        if not dest == None:
            code = dict_2get(self.transition_code, self.state, self.event)
            self.update_next_state(dest)
            code(self)
            self.update_state(dest)
            if not self.is_wait_state():
                assert self.ev_up == 1
                return True
            else:
                assert self.ev_up == 0
                return False

        elif not dest_always == None:
            code = dict_2get(self.transition_code, self.state, "always")
            self.update_next_state(dest_always)
            code(self)
            self.update_state(dest_always)
            if not self.is_wait_state():
                assert self.ev_up == 1
                return True
            else:
                assert self.ev_up == 0
                return False

        elif not eventset_dest == None:
            code = dict_2get(self.transition_code, self.state, eventset)
            self.update_next_state(eventset_dest)
            code(self)
            self.update_state(eventset_dest)
            if not self.is_wait_state():
                assert self.ev_up == 1
                return True
            else:
                assert self.ev_up == 0
                return False

        else:
            assert self.ev_up == 0
            return False

    def add_to_event_set(self, eventset, event):
        dict_put(self.valid_events, event, True)
        member_of = dict_get(self.eventsets, event)
        if member_of == None:
            dict_put(self.eventsets, event, [eventset])
        elif not member_of == None:
            member_of.append(eventset)

    def add_many_to_event_set(self, eventset, events):
        dict_put(self.rev_eventsets, eventset, events)
        for e in events:
            self.add_to_event_set(eventset, e)

    def add_transition(self, start, end, event):
        exists = dict_2get(self.transitions, start, event)
        assert exists == None
        dict_put(self.valid_events, event, True)
        dict_2put(self.transitions, start, event, end)
        dict_2put(self.heatmap, start, end, 0)

    def init_code_root(self, s):
        endo = self
        layer_1 = endo.transition_code.get(s)
        if layer_1 == None:
            endo.transition_code[s] = {}

    def initialize_machine(self):
        self.stackset.set_changeable(["state"])
        self.stackset.push("state", self.state)
        self.stackset.reset_access()
        endo = self
        self.add_many_to_event_set("@admin-blockchain-change", [
            "admin-change-stake-yield", "admin-change-max-stake",
            "admin-change-lookup-fee", "admin-change-user-fee",
            "admin-stakeable-change-yield"
        ])
        self.add_many_to_event_set("@admin-db-change", [
            "admin-change-reward-strategy", "admin-stakeable-approve",
            "admin-stakeable-reject", "admin-stakeable-close"
        ])
        self.add_many_to_event_set("@public-fetch", [
            "public-galactus-account-get", "public-stakeables-list",
            "public-stakeable-get", "public-stakeable-stake",
            "public-leaderboard-get"
        ])
        self.add_many_to_event_set("@sufficient-data-for-response", [
            "galactus-account-exists", "galactus-account-not-destroyable",
            "wallet-in-use", "galactus-account-can-login",
            "galactus-account-cannot-logout", "galactus-account-cannot-login"
        ])
        self.add_many_to_event_set("@safety-tested",
                                   ["safety-tested", "safety-tested-anon"])
        self.add_many_to_event_set(
            "@test-safety",
            ["can-test-safety-personally", "cannot-test-safety-personally"])
        self.add_many_to_event_set(
            "@public-safety",
            ["public-site-safe", "public-site-unlock", "public-site-flag"])
        self.add_many_to_event_set("@public-acct-manage", [
            "public-galactus-account-create",
            "public-galactus-account-destroy", "public-galactus-account-login",
            "public-galactus-account-logout", "public-wallet-add",
            "public-wallet-change", "public-password-forgot",
            "public-password-reset", "public-email-confirm",
            "public-email-change"
        ])
        self.add_many_to_event_set("@retry-prev-or-store-next", [
            "account-meters-stored", "galactus-store-error",
            "deleted-account-stored"
        ])
        self.add_many_to_event_set(
            "@retry-prev-or-load-next",
            ["site-loaded", "site-not-loaded", "galactus-load-error"])

        endo.add_transition("begin-here", "ready", "ignite")

        def begin_here__ready__ignite(endo):
            pre_verify()
            endo.event = None
            (exo.use_default_ilock_policy().use_default_reward_strategy().
             backoff_strategy_create(retries=0,
                                     max_delay_ms=1000,
                                     min_delay_ms=100,
                                     delay_ms=100,
                                     scale_factor=2,
                                     randomness=0.1))
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "begin-here", "ignite",
                  begin_here__ready__ignite)

        endo.add_transition("ready", "galactus-load-tried",
                            "@public-acct-manage")

        def ready__galactus_load_tried__evset_public_acct_manage(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "public-galactus-account-create":
                (exo.contextualize().galactus_account_regdatify(
                ).galactus_account_last_req().galactus_account_name_as_load().
                 data_load())
            elif br_event == "public-galactus-account-destroy":
                (exo.contextualize().galactus_account_last_req().
                 galactus_account_creds_as_load().data_load())
            elif br_event == "public-galactus-account-login":
                (exo.contextualize().galactus_account_last_req().
                 galactus_account_creds_as_load().data_load())
            elif br_event == "public-galactus-account-logout":
                (exo.contextualize().galactus_account_last_req().
                 galactus_account_key_as_load().data_load())
            elif br_event == "public-wallet-add":
                (exo.contextualize().wallet_as_load().data_load())
            elif br_event == "public-password-forgot":
                assert False
            elif br_event == "public-password-reset":
                assert False
            elif br_event == "public-email-confirm":
                assert False
            elif br_event == "public-email-change":
                assert False
            elif br_event == "public-wallet-change":
                assert False
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "@public-acct-manage",
                  ready__galactus_load_tried__evset_public_acct_manage)

        endo.add_transition("ready", "panic", "multiple-policies")

        def ready__panic__multiple_policies(endo):
            pre_verify()
            endo.event = None
            (exo.harakiri())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "multiple-policies",
                  ready__panic__multiple_policies)

        endo.add_transition("ready", "galactus-load-tried",
                            "load-reward-strategy")

        def ready__galactus_load_tried__load_reward_strategy(endo):
            pre_verify()
            endo.event = None
            (exo.contextualize().load_reward_strategy_table())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "load-reward-strategy",
                  ready__galactus_load_tried__load_reward_strategy)

        endo.add_transition("galactus-load-tried", "site-ping-tried",
                            "flaggable-loaded")

        def galactus_load_tried__site_ping_tried__flaggable_loaded(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().load_query_discard().site_ping())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-tried",
                  "flaggable-loaded",
                  galactus_load_tried__site_ping_tried__flaggable_loaded)

        endo.add_transition("site-ping-tried", "galactus-store-tried",
                            "@site-reachable")

        def site_ping_tried__galactus_store_tried__evset_site_reachable(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "site-reachable":
                (exo.stakeable_pend().stakeable_as_store().data_store())
            elif br_event == "site-unreachable":
                (exo.stakeable_shelve().stakeable_as_store().data_store())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "site-ping-tried", "@site-reachable",
                  site_ping_tried__galactus_store_tried__evset_site_reachable)

        endo.add_transition("ready", "galactus-load-tried", "@public-fetch")

        def ready__galactus_load_tried__evset_public_fetch(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "public-stakeables-list":
                (exo.contextualize().stakeables_list().data_load())
            elif br_event == "public-stakeable-get":
                (exo.contextualize().stakeable_as_load().data_load())
            elif br_event == "public-stakeable-stake":
                (exo.contextualize().stakeable_stake().data_load())
            elif br_event == "public-leaderboard-get":
                (exo.contextualize().leaderboard_get().data_load())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "@public-fetch",
                  ready__galactus_load_tried__evset_public_fetch)

        endo.add_transition("ready", "galactus-load-tried", "@public-safety")

        def ready__galactus_load_tried__evset_public_safety(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "public-site-safe":
                (exo.contextualize().galactus_account_last_req(
                ).galactus_account_meters_as_load_by_key().stakeable_as_load().
                 data_load())
            elif br_event == "public-site-unlock":
                (exo.contextualize().galactus_account_key_blocklist_as_load().
                 stakeable_as_load().data_load())
            elif br_event == "public-site-flag":
                (exo.contextualize().galactus_account_key_blocklist_as_load().
                 stakeable_as_load().data_load())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "@public-safety",
                  ready__galactus_load_tried__evset_public_safety)

        endo.add_transition("galactus-load-tried", "test-safety-tried",
                            "@test-safety")

        def galactus_load_tried__test_safety_tried__evset_test_safety(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "can-test-safety-personally":
                (exo.load_query_discard().galactus_account_increment_meters().
                 octahedron_test_site())
            elif br_event == "cannot-test-safety-personally":
                (exo.load_query_discard().octahedron_test_site())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-tried", "@test-safety",
                  galactus_load_tried__test_safety_tried__evset_test_safety)

        endo.add_transition("ready", "galactus-store-tried",
                            "@admin-db-change")

        def ready__galactus_store_tried__evset_admin_db_change(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "admin-stakeable-approve":
                (exo.contextualize().stakeable_approve())
            elif br_event == "admin-stakeable-reject":
                (exo.contextualize().stakeable_reject())
            elif br_event == "admin-stakeable-close":
                (exo.contextualize().stakeable_close())
            elif br_event == "admin-change-reward-strategy":
                (exo.contextualize().reward_strategy_change())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "@admin-db-change",
                  ready__galactus_store_tried__evset_admin_db_change)

        endo.add_transition("galactus-load-tried", "ready", "galactus-loaded")

        def galactus_load_tried__ready__galactus_loaded(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().load_query_discard().respond().stack_gc().
             decontextualize())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-tried",
                  "galactus-loaded",
                  galactus_load_tried__ready__galactus_loaded)

        endo.add_transition("galactus-load-tried", "galactus-load-tried",
                            "@retry-prev-or-load-next")

        def galactus_load_tried__galactus_load_tried__evset_retry_prev_or_load_next(
                endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "galactus-load-error":
                (exo.backoff().data_load())
            elif br_event == "site-loaded":
                # Reset backoff if we are loading more stuff, instead of recovering from error
                (exo.stakeable_visits_increment().backoff_reset().
                 load_query_discard().data_load())
            elif br_event == "site-not-loaded":
                # Reset backoff if we are loading more stuff, instead of recovering from error
                (exo.stakeable_uniqueify().stakeable_visits_increment().
                 backoff_reset().load_query_discard().data_load())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-load-tried",
            "@retry-prev-or-load-next",
            galactus_load_tried__galactus_load_tried__evset_retry_prev_or_load_next
        )

        endo.add_transition("galactus-load-tried", "notify-admin",
                            "backoff-period")

        def galactus_load_tried__notify_admin__backoff_period(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().load_query_discard().load_query_discard().
             context_log())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-tried",
                  "backoff-period",
                  galactus_load_tried__notify_admin__backoff_period)

        endo.add_transition("test-safety-tried", "galactus-store-tried",
                            "@safety-tested")

        def test_safety_tried__galactus_store_tried__evset_safety_tested(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "safety-tested":
                (exo.backoff_reset().stakeable_as_store(
                ).galactus_account_malicious_meter().
                 galactus_account_meters_as_store().data_store())
            elif br_event == "safety-tested-anon":
                (exo.backoff_reset().stakeable_as_store().data_store())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "test-safety-tried", "@safety-tested",
            test_safety_tried__galactus_store_tried__evset_safety_tested)

        endo.add_transition("test-safety-tried", "test-safety-tried",
                            "test-safety-error")

        def test_safety_tried__test_safety_tried__test_safety_error(endo):
            pre_verify()
            endo.event = None
            (exo.backoff().octahedron_test_site())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "test-safety-tried",
                  "test-safety-error",
                  test_safety_tried__test_safety_tried__test_safety_error)

        endo.add_transition("test-safety-tried", "notify-admin",
                            "backoff-period")

        def test_safety_tried__notify_admin__backoff_period(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().context_log())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "test-safety-tried", "backoff-period",
                  test_safety_tried__notify_admin__backoff_period)

        endo.add_transition("galactus-store-tried", "changes-commited",
                            "galactus-stored")

        def galactus_store_tried__changes_commited__galactus_stored(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().store_query_discard().context_log())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-store-tried",
                  "galactus-stored",
                  galactus_store_tried__changes_commited__galactus_stored)

        endo.add_transition("galactus-store-tried", "galactus-store-tried",
                            "@retry-prev-or-store-next")

        def galactus_store_tried__galactus_store_tried__evset_retry_prev_or_store_next(
                endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "galactus-store-error":
                (exo.backoff().data_store())
            elif br_event == "account-meters-stored":
                (exo.backoff_reset().store_query_discard().data_store())
            elif br_event == "deleted-account-stored":
                (exo.backoff_reset().store_query_discard().data_store())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-store-tried",
            "@retry-prev-or-store-next",
            galactus_store_tried__galactus_store_tried__evset_retry_prev_or_store_next
        )

        endo.add_transition("galactus-store-tried", "notify-admin",
                            "backoff-period")

        def galactus_store_tried__notify_admin__backoff_period(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().store_query_discard().store_query_discard().
             context_log())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-store-tried",
                  "backoff-period",
                  galactus_store_tried__notify_admin__backoff_period)

        endo.add_transition("galactus-load-tried", "ready",
                            "@sufficient-data-for-response")

        def galactus_load_tried__ready__evset_sufficient_data_for_response(
                endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "galactus-account-exists":
                (exo.backoff_reset().load_query_discard().response_create(
                    status=409).respond().stack_gc().decontextualize())
            elif br_event == "galactus-account-not-destroyable":
                (exo.backoff_reset().load_query_discard().response_create(
                    status=404).respond().stack_gc().decontextualize())
            elif br_event == "wallet-in-use":
                (exo.backoff_reset().load_query_discard().response_create(
                    status=500).respond().stack_gc().decontextualize())
            elif br_event == "galactus-account-can-login":
                (exo.backoff_reset().load_query_discard().
                 galactus_account_verify_password().response_create(
                     status=200).respond().stack_gc().decontextualize())
            elif br_event == "galactus-account-cannot-logout":
                (exo.backoff_reset().load_query_discard().response_create(
                    status=401).respond().stack_gc().decontextualize())
            elif br_event == "galactus-account-cannot-login":
                (exo.backoff_reset().load_query_discard().response_create(
                    status=401).respond().stack_gc().decontextualize())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-load-tried",
            "@sufficient-data-for-response",
            galactus_load_tried__ready__evset_sufficient_data_for_response)

        endo.add_transition("galactus-load-tried", "galactus-store-tried",
                            "galactus-account-non-existent")

        def galactus_load_tried__galactus_store_tried__galactus_account_non_existent(
                endo):
            pre_verify()
            endo.event = None
            (exo.load_query_discard().galactus_account_hashify_password().
             galactus_account_new_key().galactus_account_as_store().data_store(
             ))
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-load-tried",
            "galactus-account-non-existent",
            galactus_load_tried__galactus_store_tried__galactus_account_non_existent
        )

        endo.add_transition("galactus-load-tried", "credential-checked",
                            "galactus-account-destroyable")

        def galactus_load_tried__credential_checked__galactus_account_destroyable(
                endo):
            pre_verify()
            endo.event = None
            (exo.load_query_discard().galactus_account_verify_password().
             galactus_account_empty().is_not().event_create(
                 name="galactus-account-allow-destroy").event_create(
                     name="galactus-account-disallow-destroy").bool_eventify())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-load-tried",
            "galactus-account-destroyable",
            galactus_load_tried__credential_checked__galactus_account_destroyable
        )

        endo.add_transition("credential-checked", "galactus-store-tried",
                            "galactus-account-allow-destroy")

        def credential_checked__galactus_store_tried__galactus_account_allow_destroy(
                endo):
            pre_verify()
            endo.event = None
            # We want to store the deleted-account object first, because if we get interrupted we can always complete the delete afterwards
            # If we do it the other way around, we can end up losing the original account-object, making it impossible to keep track of deletions
            # Or we can just wrap everything in a transaction, but that makes galactus less portable
            (exo.galactus_account_as_destroy_by_key(
            ).galactus_account_deletify().deleted_galactus_account_as_store().
             data_store())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "credential-checked",
            "galactus-account-allow-destroy",
            credential_checked__galactus_store_tried__galactus_account_allow_destroy
        )

        endo.add_transition("credential-checked", "ready",
                            "galactus-account-disallow-destroy")

        def credential_checked__ready__galactus_account_disallow_destroy(endo):
            pre_verify()
            endo.event = None
            (exo.response_create(
                status=401).respond().stack_gc().decontextualize())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "credential-checked",
            "galactus-account-disallow-destroy",
            credential_checked__ready__galactus_account_disallow_destroy)

        endo.add_transition("galactus-load-tried", "galactus-store-tried",
                            "galactus-account-can-logout")

        def galactus_load_tried__galactus_store_tried__galactus_account_can_logout(
                endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().load_query_discard().galactus_account_new_key(
            ).galactus_account_new_key_as_store().data_store())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-load-tried",
            "galactus-account-can-logout",
            galactus_load_tried__galactus_store_tried__galactus_account_can_logout
        )

        endo.add_transition("notify-admin", "ready", "commited")

        def notify_admin__ready__commited(endo):
            pre_verify()
            endo.event = None
            (exo.response_create(
                status=500).respond().stack_gc().decontextualize())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "notify-admin", "commited",
                  notify_admin__ready__commited)

        endo.add_transition("changes-commited", "ready", "commited")

        def changes_commited__ready__commited(endo):
            pre_verify()
            endo.event = None
            (exo.response_create(
                status=201).respond().stack_gc().decontextualize())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "changes-commited", "commited",
                  changes_commited__ready__commited)


class Exo:
    stackset = None
    endo = None

    def set_endo(self, endo):
        self.endo = endo
        self.stackset = endo.stackset

    def verify(self):
        self.stackset.set_readable(["boolean"])
        self.stackset.set_changeable(["boolean"])
        assert self.stackset.stack_len("boolean") > 0
        val = self.stackset.pop("boolean")
        assert val
        self.stackset.reset_access()
        return self

    def is_not(self):
        self.stackset.set_changeable(["boolean"])
        self.stackset.set_readable(["boolean"])
        assert self.stackset.stack_len("boolean") > 0
        val = self.stackset.pop("boolean")
        val = not val
        self.stackset.push("boolean", val)
        self.stackset.reset_access()
        return self

    def andify(self):
        self.stackset.set_changeable(["boolean"])
        self.stackset.set_readable(["boolean"])
        assert self.stackset.stack_len("boolean") > 0
        val = self.stackset.pop("boolean")
        assert self.stackset.stack_len("boolean") > 0
        val2 = self.stackset.pop("boolean")
        val = (val and val2)
        self.stackset.push("boolean", val)
        self.stackset.reset_access()
        return self

    def orify(self):
        self.stackset.set_changeable(["boolean"])
        self.stackset.set_readable(["boolean"])
        assert self.stackset.stack_len("boolean") > 0
        val = self.stackset.pop("boolean")
        assert self.stackset.stack_len("boolean") > 0
        val2 = self.stackset.pop("boolean")
        val = (val or val2)
        self.stackset.push("boolean", val)
        self.stackset.reset_access()
        return self

    def xorify(self):
        self.stackset.set_changeable(["boolean"])
        self.stackset.set_readable(["boolean"])
        assert self.stackset.stack_len("boolean") > 0
        val = self.stackset.pop("boolean")
        assert self.stackset.stack_len("boolean") > 0
        val2 = self.stackset.pop("boolean")
        val = ((val and not val2) or (not val and val2))
        self.stackset.push("boolean", val)
        self.stackset.reset_access()
        return self

    def guarded_verify(self):
        self.stackset.set_readable(["boolean"])
        self.stackset.set_changeable(["boolean"])
        assert self.stackset.stack_len("boolean") > 0
        target = self.stackset.pop("boolean")
        guard = self.stackset.pop("boolean")
        if guard == True:
            assert target

        self.stackset.reset_access()
        return self

    def in_state(self):
        self.stackset.set_readable(["boolean", "state"])
        self.stackset.set_changeable(["boolean"])
        assert self.stackset.stack_len("boolean") > 0
        val1 = self.stackset.pop("state")
        val2 = self.stackset.peek("state")
        equal = val1 == val2
        self.push("boolean", equal)
        self.stackset.reset_access()
        return self

    def state_create(self, name):
        self.stackset.set_changeable(["state"])
        self.stackset.push("state", name)
        self.stackset.reset_access()
        return self

    def event_create(self, name):
        self.stackset.set_changeable(["event"])
        self.stackset.push("event", name)
        self.stackset.reset_access()
        return self

    def boolean_create(self, val=False):
        self.stackset.set_changeable(["boolean"])
        self.stackset.push("boolean", val)
        self.stackset.reset_access()
        return self

    def datetime_create(self, val=datetime.datetime.now()):
        self.stackset.set_changeable(["datetime"])
        self.stackset.push("datetime", val)
        self.stackset.reset_access()
        return self

    def number_create(self, val=0):
        self.stackset.set_changeable(["number"])
        self.stackset.push("number", val)
        self.stackset.reset_access()
        return self

    def string_create(self, val=""):
        self.stackset.set_changeable(["string"])
        self.stackset.push("string", val)
        self.stackset.reset_access()
        return self

    def galactus_account_empty(self):
        self.stackset.set_readable(["galactus-account", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("galactus-account")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def galactus_account_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "galactus-account"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def galactus_account_create(self,
                                locked=False,
                                api_key_expiration=datetime.datetime.now(),
                                last_request=datetime.datetime.now(),
                                api_key="",
                                referrer="",
                                referred=0,
                                registration_date=datetime.datetime.now(),
                                unlocks_confirmed=0,
                                flags_confirmed=0,
                                unlocks=0,
                                unlocks_total=0,
                                flags=0,
                                flags_total=0,
                                unique=0,
                                unique_total=0,
                                malicious=0,
                                malicious_total=0,
                                lookups=0,
                                lookups_total=0,
                                tokens_earned_total=0,
                                tokens_earned=0,
                                tokens_deducted=0,
                                tokens_deposited=0,
                                wallet_confirmed=False,
                                wallet_id="",
                                unsalted_password="",
                                salted_password="",
                                email="",
                                username=""):
        self.stackset.set_changeable(["galactus-account"])
        ret = galactus_account(
            self, locked, api_key_expiration, last_request, api_key, referrer,
            referred, registration_date, unlocks_confirmed, flags_confirmed,
            unlocks, unlocks_total, flags, flags_total, unique, unique_total,
            malicious, malicious_total, lookups, lookups_total,
            tokens_earned_total, tokens_earned, tokens_deducted,
            tokens_deposited, wallet_confirmed, wallet_id, unsalted_password,
            salted_password, email, username)
        dstack = self.stackset.stacks["galactus-account"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def deleted_galactus_account_empty(self):
        self.stackset.set_readable(["deleted-galactus-account", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("deleted-galactus-account")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def deleted_galactus_account_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "deleted-galactus-account"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def deleted_galactus_account_create(
            self,
            deletion_date=datetime.datetime.now(),
            registration_date=datetime.datetime.now(),
            username=""):
        self.stackset.set_changeable(["deleted-galactus-account"])
        ret = deleted_galactus_account(self, deletion_date, registration_date,
                                       username)
        dstack = self.stackset.stacks["deleted-galactus-account"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def site_empty(self):
        self.stackset.set_readable(["site", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("site")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def site_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "site"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def site_create(self,
                    url="",
                    flags=0,
                    unlocks=0,
                    visits=0,
                    stake_state="neutral",
                    unique=False,
                    classification=None):
        self.stackset.set_changeable(["site"])
        ret = site(self, url, flags, unlocks, visits, stake_state, unique,
                   classification)
        dstack = self.stackset.stacks["site"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def leaderboard_empty(self):
        self.stackset.set_readable(["leaderboard", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("leaderboard")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def leaderboard_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "leaderboard"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def leaderboard_create(self, dummy=0):
        self.stackset.set_changeable(["leaderboard"])
        ret = leaderboard(self, dummy)
        dstack = self.stackset.stacks["leaderboard"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def paging_control_empty(self):
        self.stackset.set_readable(["paging-control", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("paging-control")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def paging_control_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "paging-control"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def paging_control_create(self, filt="", page_num=0, quantity=0):
        self.stackset.set_changeable(["paging-control"])
        ret = paging_control(self, filt, page_num, quantity)
        dstack = self.stackset.stacks["paging-control"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def context_empty(self):
        self.stackset.set_readable(["context", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("context")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def context_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "context"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def context_create(self,
                       locked=False,
                       timestamp_end=datetime.datetime.now(),
                       timestamp_start=datetime.datetime.now(),
                       event=""):
        self.stackset.set_changeable(["context"])
        ret = context(self, locked, timestamp_end, timestamp_start, event)
        dstack = self.stackset.stacks["context"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def stochasticity_empty(self):
        self.stackset.set_readable(["stochasticity", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("stochasticity")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def stochasticity_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "stochasticity"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def stochasticity_create(self,
                             n_retries=0,
                             retries=False,
                             n_octa=0,
                             octa=False,
                             n_load=0,
                             load=False,
                             n_store=0,
                             store=False):
        self.stackset.set_changeable(["stochasticity"])
        ret = stochasticity(self, n_retries, retries, n_octa, octa, n_load,
                            load, n_store, store)
        dstack = self.stackset.stacks["stochasticity"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def db_load_query_empty(self):
        self.stackset.set_readable(["db-load-query", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("db-load-query")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def db_load_query_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "db-load-query"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def db_load_query_create(self, q=None):
        self.stackset.set_changeable(["db-load-query"])
        ret = db_load_query(self, q)
        dstack = self.stackset.stacks["db-load-query"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def db_store_query_empty(self):
        self.stackset.set_readable(["db-store-query", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("db-store-query")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def db_store_query_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "db-store-query"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def db_store_query_create(self, q=None):
        self.stackset.set_changeable(["db-store-query"])
        ret = db_store_query(self, q)
        dstack = self.stackset.stacks["db-store-query"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def ilock_policy_empty(self):
        self.stackset.set_readable(["ilock-policy", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("ilock-policy")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def ilock_policy_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "ilock-policy"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def ilock_policy_create(self,
                            max_stake=0,
                            stake_yield=0,
                            lookup_fee=0,
                            user_fee=0):
        self.stackset.set_changeable(["ilock-policy"])
        ret = ilock_policy(self, max_stake, stake_yield, lookup_fee, user_fee)
        dstack = self.stackset.stacks["ilock-policy"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def reward_strategy_empty(self):
        self.stackset.set_readable(["reward-strategy", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("reward-strategy")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def reward_strategy_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "reward-strategy"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def reward_strategy_create(self, dummy=0):
        self.stackset.set_changeable(["reward-strategy"])
        ret = reward_strategy(self, dummy)
        dstack = self.stackset.stacks["reward-strategy"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def response_empty(self):
        self.stackset.set_readable(["response", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("response")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def response_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "response"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def response_create(self, locked=False, body=None, status=200):
        self.stackset.set_changeable(["response"])
        ret = response(self, locked, body, status)
        dstack = self.stackset.stacks["response"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def octa_verdict_empty(self):
        self.stackset.set_readable(["octa-verdict", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("octa-verdict")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def octa_verdict_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "octa-verdict"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def octa_verdict_create(self, safe=False):
        self.stackset.set_changeable(["octa-verdict"])
        ret = octa_verdict(self, safe)
        dstack = self.stackset.stacks["octa-verdict"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def backoff_strategy_empty(self):
        self.stackset.set_readable(["backoff-strategy", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("backoff-strategy")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def backoff_strategy_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "backoff-strategy"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def backoff_strategy_create(self,
                                randomness=0,
                                retries=0,
                                scale_factor=0,
                                max_delay_ms=0,
                                delay_ms=0,
                                min_delay_ms=0):
        self.stackset.set_changeable(["backoff-strategy"])
        ret = backoff_strategy(self, randomness, retries, scale_factor,
                               max_delay_ms, delay_ms, min_delay_ms)
        dstack = self.stackset.stacks["backoff-strategy"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def db_error_empty(self):
        self.stackset.set_readable(["db-error", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("db-error")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def db_error_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "db-error"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def db_error_create(self, e=""):
        self.stackset.set_changeable(["db-error"])
        ret = db_error(self, e)
        dstack = self.stackset.stacks["db-error"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def blockchain_error_empty(self):
        self.stackset.set_readable(["blockchain-error", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("blockchain-error")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def blockchain_error_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "blockchain-error"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def blockchain_error_create(self, e=""):
        self.stackset.set_changeable(["blockchain-error"])
        ret = blockchain_error(self, e)
        dstack = self.stackset.stacks["blockchain-error"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def octahedron_error_empty(self):
        self.stackset.set_readable(["octahedron-error", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("octahedron-error")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def octahedron_error_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "octahedron-error"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def octahedron_error_create(self, e=""):
        self.stackset.set_changeable(["octahedron-error"])
        ret = octahedron_error(self, e)
        dstack = self.stackset.stacks["octahedron-error"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def input_error_empty(self):
        self.stackset.set_readable(["input-error", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("input-error")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def input_error_length(self):
        self.stackset.set_changeable(["number"])
        l = len(dict_get(self.stackset.stacks, "input-error"))
        self.stackset.push("number", l)
        self.stackset.reset_access()
        return self

    def input_error_create(self, e=""):
        self.stackset.set_changeable(["input-error"])
        ret = input_error(self, e)
        dstack = self.stackset.stacks["input-error"]
        dstack.append(ret)
        self.stackset.reset_access()
        return self

    def use_default_ilock_policy(self):
        exo = self
        self.stackset.set_readable([])
        self.stackset.set_changeable(["ilock-policy"])
        (exo.ilock_policy_create(user_fee=69,
                                 lookup_fee=69,
                                 stake_yield=69,
                                 max_stake=69))
        self.stackset.reset_access()
        return self

    def use_default_reward_strategy(self):
        exo = self
        self.stackset.set_readable([])
        self.stackset.set_changeable(["reward-strategy"])
        # TODO finish this by defining the various reward-strategy-parameters in the class
        (exo.reward_strategy_create(dummy=69))
        self.stackset.reset_access()
        return self

    def genome_compute(self):
        exo = self
        self.stackset.set_readable(["number"])
        self.stackset.set_changeable(["number"])
        # TODO finish me
        # TODO we assume we pushed the price-delta, user-progress, fxr onto the stack in that order
        genome = {
            "stim-contradiction-rate-change-max-stake": 0,
            "stim-anti-user-goal-progress-change-max-stake": 0,
            "stim-token-price-delta-change-max-stake": 0,
            "stim-contradiction-rate-change-stake-yield": 0,
            "stim-anti-user-goal-progress-change-stake-yield": 0,
            "stim-token-price-delta-change-stake-yield": 0,
            "stim-contradiction-rate-change-lookup-fee": 0,
            "stim-anti-user-goal-progress-change-lookup-fee": 0,
            "stim-token-price-delta-change-lookup-fee": 0,
            "stim-contradiction-rate-change-user-fee": 1,
            "stim-anti-user-goal-progress-change-user-fee": 0,
            "stim-token-price-delta-change-user-fee": 0,
            "stim-contradiction-rate-change-buyback-amount": 0,
            "stim-anti-user-goal-progress-change-buyback-amount": 0,
            "stim-token-price-delta-change-buyback-amount": 0,
            "stim-contradiction-rate-change-sell-amount": 0,
            "stim-anti-user-goal-progress-change-sell-amount": 0,
            "stim-token-price-delta-change-sell-amount": 0,
            "stim-contradiction-rate-change-reward-amount": 0,
            "stim-anti-user-goal-progress-change-reward-amount": -0.66,
            "stim-token-price-delta-change-reward-amount": -0.33,
            "stim-contradiction-rate-change-urgency": 1,
            "stim-anti-user-goal-progress-change-urgency": 0,
            "stim-token-price-delta-change-urgency": 0
        }
        price_delta = self.stackset.pop("number")
        user_goal_prog = self.stackset.pop("number")
        fxr = self.stackset.pop("number")
        # TODO do the summing and multiplication
        # INFO change-research-urgency is informational like a warning
        change_urgency = 0
        # INFO these are advisory changes that cannot (or are difficult) to automate
        change_sell_amount = 0
        change_buyback_amount = 0
        # INFO these are advisory changes that can be automated
        change_reward_amount = 0
        change_user_fee = 0
        change_lookup_fee = 0
        change_max_stake = 0
        change_stake_yield = 0
        self.stackset.reset_access()
        return self

    def have_username(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("galactus-account")
        gau = ga.username
        b = (isinstance(gau, str) and not gau == "")
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def account_regdate_after_context_timestamp(self):
        exo = self
        self.stackset.set_readable(["context", "galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("galactus-account")
        if not ga == None:
            gard = ga.registration_date
            ctx = self.stackset.peek("context")
            if not ctx == None:
                ts = ctx.timestamp_start
                b = ts <= gard
                self.stackset.push("boolean", b)
            else:
                self.stackset.push("boolean", False)

        else:
            self.stackset.push("boolean", False)

        self.stackset.reset_access()
        return self

    def regdel_dates_sane(self):
        exo = self
        self.stackset.set_readable(["deleted-galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("deleted-galactus-account")
        gard = ga.registration_date
        gadd = ga.deletion_date
        b = gard < gadd
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def have_wallet_id(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("galactus-account")
        gawi = ga.wallet_id
        # TODO make this test actually work in post-MVP future
        b = True
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def have_api_key(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("galactus-account")
        gaak = ga.api_key
        b = len(gaak) > 0
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def have_either_salted_or_unsalted_password(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("galactus-account")
        gaspw = ga.salted_password
        gaupw = ga.unsalted_password
        b1 = (isinstance(gaspw, str) and not gaspw == "")
        b2 = (isinstance(gaupw, str) and not gaupw == "")
        self.stackset.push("boolean", ((b1 and not b2) or (not b1 and b2)))
        self.stackset.reset_access()
        return self

    def page_quantity_one_plus(self):
        exo = self
        self.stackset.set_readable(["paging-control"])
        self.stackset.set_changeable(["boolean"])
        pc = self.stackset.peek("paging-control")
        q = pc.quantity
        b = q > 0
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def page_num_zero_plus(self):
        exo = self
        self.stackset.set_readable(["paging-control"])
        self.stackset.set_changeable(["boolean"])
        pc = self.stackset.peek("paging-control")
        pn = pc.page_num
        b = pn >= 0
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def number_eq(self):
        exo = self
        self.stackset.set_readable(["number"])
        self.stackset.set_changeable(["number", "boolean"])
        n1 = self.stackset.pop("number")
        n2 = self.stackset.pop("number")
        b = n1 >= n2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def number_gteq(self):
        exo = self
        self.stackset.set_readable(["number"])
        self.stackset.set_changeable(["number", "boolean"])
        n1 = self.stackset.pop("number")
        n2 = self.stackset.pop("number")
        b = n1 >= n2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def number_lteq(self):
        exo = self
        self.stackset.set_readable(["number"])
        self.stackset.set_changeable(["number", "boolean"])
        n1 = self.stackset.pop("number")
        n2 = self.stackset.pop("number")
        b = n1 <= n2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def number_gt(self):
        exo = self
        self.stackset.set_readable(["number"])
        self.stackset.set_changeable(["number", "boolean"])
        n1 = self.stackset.pop("number")
        n2 = self.stackset.pop("number")
        b = n1 > n2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def number_lt(self):
        exo = self
        self.stackset.set_readable(["number"])
        self.stackset.set_changeable(["number", "boolean"])
        n1 = self.stackset.pop("number")
        n2 = self.stackset.pop("number")
        b = n1 < n2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def state_is(self):
        exo = self
        self.stackset.set_readable(["state"])
        self.stackset.set_changeable(["state", "boolean"])
        s1 = self.stackset.pop("state")
        assert self.stackset.stack_len("state") > 0
        s2 = self.stackset.peek("state")
        b = s1 == s2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def prev_state_is(self):
        exo = self
        self.stackset.set_readable(["prev-state", "state"])
        self.stackset.set_changeable(["state", "boolean"])
        s1 = self.stackset.pop("state")
        assert self.stackset.stack_len("state") > 0
        s2 = self.stackset.peek("prev-state")
        b = s1 == s2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def next_state_is(self):
        exo = self
        self.stackset.set_readable(["next-state", "state"])
        self.stackset.set_changeable(["state", "boolean"])
        s1 = self.stackset.pop("state")
        assert self.stackset.stack_len("state") > 0
        s2 = self.stackset.peek("next-state")
        b = s1 == s2
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def end_after_start(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["boolean"])
        ctx = self.stackset.peek("context")
        ts = ctx.timestamp_start
        te = ctx.timestamp_end
        b = ts <= te
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def load_query_exists(self):
        exo = self
        self.stackset.set_readable(["db-load-query"])
        self.stackset.set_changeable(["boolean"])
        dbq = self.stackset.peek("db-load-query")
        q = dbq.q
        b = not q == None
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def store_query_exists(self):
        exo = self
        self.stackset.set_readable(["db-store-query"])
        self.stackset.set_changeable(["boolean"])
        dbq = self.stackset.peek("db-store-query")
        q = dbq.q
        b = not q == None
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def harakiri(self):
        exo = self
        self.stackset.set_readable([])
        self.stackset.set_changeable([])
        assert False
        self.stackset.reset_access()
        return self

    def contextualize(self):
        exo = self
        self.stackset.set_readable(["event"])
        self.stackset.set_changeable(["response", "context"])
        assert self.stackset.stack_len("event") > 0
        # Typically, the FAPI response handler cleans up the response stack, but this is here just in case
        self.stackset.pop("response")
        ev = self.stackset.peek("event")
        ts = datetime.datetime.now()
        self.stackset.pop("context")
        self.context_create(event=ev, timestamp_start=ts)
        self.stackset.reset_access()
        return self

    def decontextualize(self):
        exo = self
        self.stackset.set_readable([])
        self.stackset.set_changeable(["context"])
        self.stackset.pop("context")
        self.stackset.reset_access()
        return self

    def context_log(self):
        exo = self
        self.stackset.set_readable(["next-state", "context"])
        self.stackset.set_changeable([])
        # We happen to use sqlite for logging as a convenience
        # However, this verb is meant to abstract that detail away
        # Which is why we build the query and we try to 'log'/insert the context (instead of using the *-as-store and data-store verbs)
        # If the insert fails, we do not retry and instead trip an assert
        assert self.stackset.stack_len("context") > 0
        ctx = self.stackset.peek("context")
        ctx.timestamp_end = datetime.datetime.now()
        ctx.locked = True
        # TODO use db_engine_log to write context object
        # TODO we should also write the failure type (load/store/test-safety) and the target-site (if any)
        self.endo.update_event("commited", None)
        self.stackset.reset_access()
        return self

    def context_is(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["boolean", "context"])
        assert self.stackset.stack_len("context") > 0
        ctx1 = self.stackset.pop("context")
        ctx2 = self.stackset.peek("context")
        if ctx2 == None:
            self.stackset.push("boolean", False)
        else:
            b = ctx1.event == ctx2.event
            self.stackset.push("boolean", b)

        self.stackset.reset_access()
        return self

    def context_is_locked(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["boolean"])
        ctx = self.stackset.peek("context")
        ctxl = ctx.locked
        self.stackset.push("boolean", ctxl)
        self.stackset.reset_access()
        return self

    def data_load(self):
        exo = self
        self.stackset.set_readable([
            "galactus-account", "context", "db-load-query", "prev-event",
            "event"
        ])
        self.stackset.set_changeable(
            ["db-error", "site", "leaderboard", "galactus-account"])
        assert self.stackset.stack_len("db-load-query") > 0
        assert self.stackset.stack_len("context") > 0
        dbq = self.stackset.peek("db-load-query")
        q = dbq.q
        ctx = self.stackset.peek("context")
        ev = ctx.event
        pevlast = self.stackset.peek("prev-event")
        evlast = self.stackset.peek("event")
        if not evlast == "backoff-period":
            # We have been told to keep re/trying
            try:
                with db_engine_main.connect() as conn:
                    if ev == "public-galactus-account-create":
                        rows = conn.execute(q)
                        row = rows.first()
                        if not row == None:
                            self.endo.update_event("galactus-account-exists",
                                                   None)
                        elif row == None:
                            self.endo.update_event(
                                "galactus-account-non-existent", None)

                    elif ev == "public-galactus-account-destroy":
                        rows = conn.execute(q)
                        row = rows.first()
                        if not row == None:
                            phash = row[0]
                            key = row[1]
                            key_exp = row[2]
                            username = row[3]
                            email = row[4]
                            exo.galactus_account_create(
                                salted_password=phash,
                                api_key=key,
                                api_key_expiration=key_exp,
                                username=username,
                                email=email)
                            self.endo.update_event(
                                "galactus-account-destroyable", None)
                        elif row == None:
                            self.endo.update_event(
                                "galactus-account-not-destroyable", None)

                    elif ev == "public-galactus-account-login":
                        rows = conn.execute(q)
                        row = rows.first()
                        if not row == None:
                            # We use the column order found in galactus_account_creds_as_load
                            phash = row[0]
                            key = row[1]
                            key_exp = row[2]
                            username = row[3]
                            email = row[4]
                            exo.galactus_account_create(
                                salted_password=phash,
                                api_key=key,
                                api_key_expiration=key_exp,
                                username=username,
                                email=email)
                            self.endo.update_event(
                                "galactus-account-can-login", None)
                        elif row == None:
                            self.endo.update_event(
                                "galactus-account-cannot-login", None)

                    elif ev == "public-galactus-account-logout":
                        rows = conn.execute(q)
                        row = rows.first()
                        if not row == None:
                            key = row[0]
                            username = row[1]
                            ga = self.stackset.peek("galactus-account")
                            lastreq = ga.last_request
                            exo.galactus_account_create(
                                salted_password='placeholder',
                                api_key=key,
                                username=username,
                                last_request=lastreq)
                            if username == ga.username:
                                self.endo.update_event(
                                    "galactus-account-can-logout", None)
                            elif not username == ga.username:
                                self.endo.update_event(
                                    "galactus-account-cannot-logout", None)

                        elif row == None:
                            self.endo.update_event(
                                "galactus-account-cannot-logout", None)

                    elif ev == "public-galactus-account-get":
                        rows = conn.execute(q)
                        row = rows.first()
                        if row == None:
                            self.endo.update_event(
                                "galactus-account-non-existent", None)
                        elif not row == None:
                            assert False

                    elif ev == "public-site-safe":
                        rows = conn.execute(q)
                        row = rows.first()
                        # We know that we tried to load a site if evlast is not a relevant event, or if pevlast is relevant and evlast is error
                        site_load_context = (
                            not (evlast == "site-loaded"
                                 or evlast == "site-not-loaded")
                            or (evlast == "galactus-load-error" and
                                (pevlast == "site-loaded"
                                 or pevlast == "site-not-loaded")))
                        if row == None:
                            if site_load_context == True:
                                self.endo.update_event("site-not-loaded", None)
                            else:
                                self.endo.update_event(
                                    "cannot-test-safety-personally", None)

                        elif not row == None:
                            if site_load_context == True:
                                url = row[0]
                                visits = row[1]
                                assert visits >= 0
                                unlocks = row[2]
                                assert unlocks >= 0
                                flags = row[3]
                                assert flags >= 0
                                stake_state = row[4]
                                assert len(stake_state) > 0
                                exo.site_create(unique=False,
                                                url=url,
                                                visits=visits,
                                                unlocks=unlocks,
                                                flags=flags,
                                                stake_state=stake_state)
                                self.endo.update_event("site-loaded", None)
                            else:
                                username = row[0]
                                email = row[1]
                                salted_password = row[2]
                                tokens_deposited = row[3]
                                tokens_deducted = row[4]
                                malicious = row[5]
                                assert malicious >= 0
                                unique = row[6]
                                assert unique >= 0
                                lookups = row[7]
                                assert lookups >= 0
                                exo.galactus_account_create(
                                    username=username,
                                    email=email,
                                    salted_password=salted_password,
                                    tokens_deposited=tokens_deposited,
                                    tokens_deducted=tokens_deducted,
                                    malicious=malicious,
                                    unique=unique,
                                    lookups=lookups)
                                self.endo.update_event(
                                    "can-test-safety-personally", None)

                    elif ev == "public-stakeable-get":
                        rows = conn.execute(q)
                        row = rows.first()
                    elif (ev == "public-site-unlock"
                          or ev == "public-site-flag"
                          or ev == "public-site-forget"):
                        # TODO Use JOIN here (see galactus_account_key_blocklist_as_load
                        assert False
                        dbqls = self.stackset.peek_list("db-load-query")
                        q_ga = dbqls[0]
                        q_uab = dbqls[1]
                        q_ss = dbqls[2]
                        user_rows = conn.execute(q_ga)
                        # TODO misusing cursor object below
                        assert False
                        if len(user_rows) > 0:
                            if ev == "public-site-forget":
                                xyz = 123
                                assert False
                            else:
                                allow_block_rows = conn.execute(q_uab)

                        site_rows = conn.execute(q_ss)
                        if len(rows) == 0:
                            self.endo.update_event("stakeable-non-existent",
                                                   None)
                        elif len(rows) > 0:
                            for r in rows:
                                xyz = 123
                                assert False

                            self.endo.update_event("stakeable-exists", None)

            except exc.DisconnectionError as e:
                # Retryable
                self.endo.update_event("galactus-load-error", None)

            except exc.TimeoutError as e:
                # Retryable
                self.endo.update_event("galactus-load-error", None)

            except exc.ArgumentError as e:
                # Non Retryable
                self.endo.update_event("backoff-period", None)

            except exc.CompileError as e:
                # Non Retryable
                self.endo.update_event("backoff-period", None)

            except exc.SQLAlchemyError:
                # Non Retryable
                self.endo.update_event("backoff-period", None)

        self.stackset.reset_access()
        return self

    def data_store(self):
        exo = self
        self.stackset.set_readable(
            ["prev-event", "event", "context", "db-store-query"])
        self.stackset.set_changeable(["db-error"])
        assert self.stackset.stack_len("db-store-query") > 0
        dbq = self.stackset.peek("db-store-query")
        q = dbq.q
        ctx = self.stackset.peek("context")
        ev = ctx.event
        evlast = self.stackset.peek("event")
        pevlast = self.stackset.peek("prev-event")
        if not evlast == "backoff-period":
            # We have been told to keep re/trying
            try:
                with db_engine_main.connect() as conn:
                    result = conn.execute(q)
                    conn.commit()
                    if ev == "public-site-safe":
                        account_store_context = (
                            (evlast == "safety-tested"
                             or evlast == "safety-tested-anon")
                            or (evlast == "galactus-store-error" and
                                (pevlast == "safety-tested"
                                 or pevlast == "safety-tested-anon")))
                        if account_store_context == True:
                            self.endo.update_event("account-meters-stored",
                                                   None)
                        else:
                            self.endo.update_event("galactus-stored", None)

                    elif ev == "public-galactus-account-destroy":
                        deleted_account_store_context = (
                            evlast == "galactus-account-allow-destroy" or
                            (evlast == "galactus-store-error"
                             and pevlast == "galactus-account-allow-destroy"))
                        if deleted_account_store_context == True:
                            self.endo.update_event("deleted-account-stored",
                                                   None)
                        else:
                            self.endo.update_event("galactus-stored", None)

                    else:
                        # All other contexts are straight forward
                        self.endo.update_event("galactus-stored", None)

            except exc.DisconnectionError as e:
                # Retryable
                self.endo.update_event("galactus-store-error", None)

            except exc.TimeoutError as e:
                # Retryable
                self.endo.update_event("galactus-store-error", None)

            except exc.ArgumentError as e:
                # Non Retryable
                self.endo.update_event("backoff-period", None)

            except exc.CompileError as e:
                # Non Retryable
                self.endo.update_event("backoff-period", None)

            except exc.SQLAlchemyError:
                # Non Retryable
                self.endo.update_event("backoff-period", None)

        self.stackset.reset_access()
        return self

    def stack_gc(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["galactus-account", "site"])
        ctx = self.stackset.peek("context")
        event = ctx.event
        if event == "public-galactus-account-create":
            self.stackset.pop("galactus-account")
        elif event == "public-galactus-account-destroy":
            self.stackset.pop("galactus-account")
            self.stackset.pop("galactus-account")
        elif event == "public-galactus-account-logout":
            self.stackset.pop("galactus-account")
            self.stackset.pop("galactus-account")
        elif event == "public-galactus-account-login":
            self.stackset.pop("galactus-account")
            self.stackset.pop("galactus-account")
        elif event == "public-site-safe":
            self.stackset.pop("galactus-account")
            self.stackset.pop("site")
            self.stackset.pop("site")
        else:
            assert False

        self.stackset.reset_access()
        return self

    def load_query_discard(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["db-load-query"])
        self.stackset.pop("db-load-query")
        self.stackset.reset_access()
        return self

    def store_query_discard(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["db-store-query"])
        self.stackset.pop("db-store-query")
        self.stackset.reset_access()
        return self

    def galactus_account_regdatify(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable([])
        ga = self.stackset.peek("galactus-account")
        ga.registration_date = datetime.datetime.now()
        self.stackset.reset_access()
        return self

    def galactus_account_deletify(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["deleted-galactus-account"])
        ga = self.stackset.peek("galactus-account")
        username = ga.username
        regdate = ga.registration_date
        deldate = ga.last_request
        self.deleted_galactus_account_create(username=username,
                                             registration_date=regdate,
                                             deletion_date=deldate)
        self.stackset.reset_access()
        return self

    def galactus_account_name_as_load(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        assert self.stackset.stack_len("galactus-account") > 0
        ga = self.stackset.peek("galactus-account")
        gaun = ga.username
        q = sql.select(galactus_account_table.c.username)
        q = q.where(galactus_account_table.c.username == gaun)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_key_as_load(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        ga = self.stackset.peek("galactus-account")
        gak = ga.api_key
        q = sql.select(galactus_account_table.c.api_key,
                       galactus_account_table.c.username)
        q = q.where(galactus_account_table.c.api_key == gak)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_key_blocklist_as_load(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        ga = self.stackset.peek("galactus-account")
        gak = ga.api_key
        # TODO Finish this, should LEFT OUTER JOIN galactus_account with block_allow_list and filter by API key
        assert False
        q = sql.select(galactus_account_table.c.username)
        q = q.where(galactus_account_table.c.api_key == gak)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def bool_eventify(self):
        exo = self
        self.stackset.set_readable([])
        self.stackset.set_changeable(
            ["next-event", "prev-event", "event", "boolean"])
        # We emit event f_e if bool is false, and event t_e if bool is true, popping all 3
        # This lets us compose non-event-emitting verbs in such a way that they can emit events without having to be rewritten to do so
        # Such rewriting would result in code-duplication (because the non-event-emitting verb was needed for other reasons)
        f_e = self.stackset.pop("event")
        t_e = self.stackset.pop("event")
        b = self.stackset.pop("boolean")
        if b == True:
            exo.endo.update_event(t_e, None)
        elif b == False:
            exo.endo.update_event(f_e, None)

        self.stackset.reset_access()
        return self

    def galactus_account_verify_password(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["galactus-account"])
        ga_loaded = self.stackset.pop("galactus-account")
        ga_inputed = self.stackset.pop("galactus-account")
        ga_loaded.last_request = ga_inputed.last_request
        pw_hash = ga_loaded.salted_password
        pw_txt = ga_inputed.unsalted_password
        is_match = verify_password(pw_hash, pw_txt)
        if is_match == True:
            # Push account back onto stack so we can use api-key in object
            self.stackset.push("galactus-account", ga_loaded)

        # Otherwise we do nothing and the account-stack stays empty
        self.stackset.reset_access()
        return self

    def galactus_account_as_load(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        ga = self.stackset.peek("galactus-account")
        gaun = ga.username
        q = sql.select(galactus_account_table)
        q = q.where(galactus_account_table.c.username == gaun)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_creds_as_load(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        ga = self.stackset.peek("galactus-account")
        gaun = ga.username
        q = sql.select(galactus_account_table.c.salted_password,
                       galactus_account_table.c.api_key,
                       galactus_account_table.c.api_key_expiration,
                       galactus_account_table.c.username,
                       galactus_account_table.c.email)
        q = q.where(galactus_account_table.c.username == gaun)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_increment_meters(self):
        exo = self
        self.stackset.set_readable(["context", "site", "galactus-account"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        ga = self.stackset.peek("galactus-account")
        ctx = self.stackset.peek("context")
        if s.unique == True:
            ga.unique = (ga.unique + 1)

        ga.lookups = (ga.lookups + 1)
        # We increment malicious in a different verb only after we talk to octahedron
        if ctx.event == "public-site-flag":
            ga.flags = (ga.flags + 1)
        elif ctx.event == "public-site-unlock":
            ga.unlocks = (ga.unlocks + 1)

        self.stackset.reset_access()
        return self

    def galactus_account_malicious_meter(self):
        exo = self
        self.stackset.set_readable(["context", "site", "galactus-account"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        ga = self.stackset.peek("galactus-account")
        ctx = self.stackset.peek("context")
        if s.unique == True:
            ga.unique = (ga.unique + 1)

        ga.lookups = (ga.lookups + 1)
        # We increment malicious in a different verb only after we talk to octahedron
        if ctx.event == "public-site-safe":
            if s.classification == True:
                ga.malicious = (ga.malicious + 1)

        else:
            assert False

        self.stackset.reset_access()
        return self

    def galactus_account_meters_as_load_by_key(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        ga = self.stackset.peek("galactus-account")
        gaak = ga.api_key
        q = sql.select(galactus_account_table.c.username,
                       galactus_account_table.c.email,
                       galactus_account_table.c.salted_password,
                       galactus_account_table.c.tokens_deposited,
                       galactus_account_table.c.tokens_deducted,
                       galactus_account_table.c.malicious,
                       galactus_account_table.c.unique,
                       galactus_account_table.c.lookups)
        q = q.where(galactus_account_table.c.username == gaak)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_has_new_api_key(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["boolean"])
        new = self.stackset.peek("galactus-account")
        old = self.stackset.peek_n("galactus-account", 0)
        if (new and old):
            b = not new.api_key == old.api_key
            self.stackset.push("boolean", b)
        else:
            self.stackset.push("boolean", True)

        self.stackset.reset_access()
        return self

    def galactus_account_as_load_by_key(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        ga = self.stackset.peek("galactus-account")
        gaak = ga.api_key
        q = sql.select(galactus_account_table)
        q = q.where(galactus_account_table.c.api_key == gaak)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_hashify_password(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable([])
        ga = self.stackset.peek("galactus-account")
        ga.locked = False
        p = ga.salted_password
        ga.salted_password = hash_password(ga.unsalted_password)
        ga.unsalted_password = p
        ga.locked = True
        self.stackset.reset_access()
        return self

    def galactus_account_new_key(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable([])
        ga = self.stackset.peek("galactus-account")
        ga.locked = False
        ga.api_key = str(uuid4())
        ga.api_key_expiration = (datetime.datetime.now() +
                                 datetime.timedelta(weeks=+4))
        ga.locked = True
        self.stackset.reset_access()
        return self

    def deleted_galactus_account_as_store(self):
        exo = self
        self.stackset.set_readable(["deleted-galactus-account"])
        self.stackset.set_changeable(["db-store-query"])
        dga = self.stackset.peek("deleted-galactus-account")
        dgaun = dga.username
        dgard = dga.registration_date
        dgadd = dga.deletion_date
        q = sql.insert(deleted_galactus_account_table)
        q = q.values(username=dgaun,
                     registration_date=dgard,
                     deletion_date=dgadd)
        exo.db_store_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_as_store(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-store-query"])
        ga = self.stackset.peek("galactus-account")
        gaun = ga.username
        gasp = ga.salted_password
        gaak = ga.api_key
        gaem = ga.email
        q = sql.insert(galactus_account_table)
        q = q.values(username=gaun,
                     salted_password=gasp,
                     api_key=gaak,
                     email=gaem)
        exo.db_store_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_meters_as_store(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-store-query"])
        ga = self.stackset.peek("galactus-account")
        gaak = ga.api_key
        gaf = ga.flags
        gaul = ga.unlocks
        gau = ga.unique
        gam = ga.malicious
        galn = ga.lookups
        q = sql.update(galactus_account_table)
        q = q.where(galactus_account_table.c.api_key == gaak)
        q = q.values(flags=gaf,
                     unlocks=gaul,
                     unique=gau,
                     malicious=gam,
                     lookups=galn)
        exo.db_store_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_as_destroy_by_key(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-store-query"])
        ga = self.stackset.peek("galactus-account")
        gaak = ga.api_key
        q = sql.delete(galactus_account_table)
        q = q.where(galactus_account_table.c.api_key == gaak)
        exo.db_store_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_new_key_as_store(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-store-query"])
        ga_new = self.stackset.peek("galactus-account")
        ga_old = self.stackset.peek_n("galactus-account", 0)
        ganak = ga_new.api_key
        gaoak = ga_old.api_key
        reqt = ga_old.last_request
        q = sql.update(galactus_account_table)
        q = q.where(galactus_account_table.c.api_key == gaoak)
        q = q.values(api_key=ganak, last_request=reqt)
        exo.db_store_query_create(q=q)
        self.stackset.reset_access()
        return self

    def galactus_account_last_req(self):
        exo = self
        self.stackset.set_readable(["context", "galactus-account"])
        self.stackset.set_changeable([])
        ga = self.stackset.peek("galactus-account")
        ctx = self.stackset.peek("context")
        ga.last_request = ctx.timestamp_start
        self.stackset.reset_access()
        return self

    def galactus_account_has_last_req(self):
        exo = self
        self.stackset.set_readable(["context", "galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("galactus-account")
        if not ga == None:
            lr = ga.last_request
            ctx = self.stackset.peek("context")
            if not ctx == None:
                ts = ctx.timestamp_start
                b = ts == lr
                self.stackset.push("boolean", b)
            else:
                self.stackset.push("boolean", True)

        else:
            self.stackset.push("boolean", True)

        self.stackset.reset_access()
        return self

    def galactus_account_is_locked(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["boolean"])
        ga = self.stackset.peek("galactus-account")
        gal = ga.locked
        self.stackset.push("boolean", gal)
        self.stackset.reset_access()
        return self

    def response_is_locked(self):
        exo = self
        self.stackset.set_readable(["response"])
        self.stackset.set_changeable(["boolean"])
        r = self.stackset.peek("response")
        if r == None:
            self.stackset.push("boolean", False)
        else:
            rl = r.locked
            self.stackset.push("boolean", rl)

        self.stackset.reset_access()
        return self

    def ilock_policy_as_load(self):
        exo = self
        self.stackset.set_readable(["ilock-policy"])
        self.stackset.set_changeable(["db-load-query"])
        ip = self.stackset.peek("ilock-policy")
        ipuf = ip.user_fee
        iplf = ip.lookup_fee
        ipsy = ip.stake_yield
        ipms = ip.max_stake
        q = sql.select(ilock_policy_table)
        # TODO wrong, also not used anymore
        q = q.where(user_fee=ipuf,
                    lookup_fee=iplf,
                    stake_yield=ipsy,
                    max_stake=ipms)
        exo.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def ilock_policy_table_as_load(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-load-query"])
        q = sql.select(ilock_policy_table)
        exo.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def ilock_policy_as_store(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["db-store-query"])
        # TODO determine if we ever want to store policies
        # there is a case to be made against this (i.e. policy changes should correspond
        # to upgrades and require commit-approval)
        xyz = 123
        assert False
        self.stackset.reset_access()
        return self

    def stake_state_valid(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable(["boolean"])
        s = self.stackset.peek("site")
        ss = s.stake_state
        if ss == "neutral":
            self.stackset.push("boolean", True)
        elif ss == "stake-pending":
            self.stackset.push("boolean", True)
        elif ss == "stake-rejected":
            self.stackset.push("boolean", True)
        elif ss == "stake-shelved":
            self.stackset.push("boolean", True)
        elif ss == "stake-approved":
            self.stackset.push("boolean", True)
        elif ss == "stake-closed":
            self.stackset.push("boolean", True)
        else:
            self.stackset.push("boolean", False)

        self.stackset.reset_access()
        return self

    def stakeable_pend(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.stake_state = "stake-pending"
        self.stackset.reset_access()
        return self

    def stakeable_shelve(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.stake_state = "stake-shelved"
        self.stackset.reset_access()
        return self

    def stakeable_as_store(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable(["db-store-query"])
        s = self.stackset.peek("site")
        ss = s.stake_state
        sv = s.visits
        sul = s.unlocks
        sf = s.flags
        su = s.url
        # sqlalchemy only exposes on_conflict_do_update as part of pgsql or sqlite
        # because we have a test mode and non-test-mode, we need to use one or the other explicitly
        q = None
        if galactus_test_mode == True:
            q = sqlite.insert(site_table)
        else:
            q = pgsql.insert(site_table)

        q = q.values(stake_state=ss, visits=sv, unlocks=sul, flags=sf, url=su)
        q = q.on_conflict_do_update(index_elements=["url"],
                                    set_={
                                        "stake_state": ss,
                                        "visits": sv,
                                        "unlocks": sul,
                                        "flags": sf
                                    })
        exo.db_store_query_create(q=q)
        self.stackset.reset_access()
        return self

    def stakeable_visits_increment(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.visits = (s.visits + 1)
        self.stackset.reset_access()
        return self

    def stakeable_flags_increment(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.flags = (s.flags + 1)
        self.stackset.reset_access()
        return self

    def stakeable_unlocks_increment(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.unlocks = (s.unlocks + 1)
        self.stackset.reset_access()
        return self

    def stakeable_uniqueify(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.unique = True
        self.stackset.reset_access()
        return self

    def stakeable_as_load(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable(["db-load-query"])
        s = self.stackset.peek("site")
        su = s.url
        q = sql.select(site_table.c.url, site_table.c.visits,
                       site_table.c.unlocks, site_table.c.flags,
                       site_table.c.stake_state)
        q = q.where(site_table.c.url == su)
        self.db_load_query_create(q=q)
        self.stackset.reset_access()
        return self

    def stakeables_list(self):
        exo = self
        self.stackset.set_readable(["page"])
        self.stackset.set_changeable(["site"])
        # TODO this is dead code and should be removed
        xyz = 123
        self.stackset.reset_access()
        return self

    def stakeable_stake(self):
        exo = self
        self.stackset.set_readable(["site", "page"])
        self.stackset.set_changeable(["site"])
        # TODO need to distinguish between being creator of stakeable and a mere staker
        xyz = 123
        self.stackset.reset_access()
        return self

    def stakeable_approve(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.stake_state = "stake-approved"
        self.stackset.reset_access()
        return self

    def stakeable_reject(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.stake_state = "stake-rejected"
        self.stackset.reset_access()
        return self

    def stakeable_close(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("site")
        s.stake_state = "stake-closed"
        self.stackset.reset_access()
        return self

    def leaderboard_get(self):
        exo = self
        self.stackset.set_readable(["site", "page"])
        self.stackset.set_changeable(["site"])
        # TODO leaderboards are computed from the galactus-account table
        # this verb should generate a load-query, and maybe have an *-as-* name
        xyz = 123
        self.stackset.reset_access()
        return self

    def reward_strategy_change(self):
        exo = self
        self.stackset.set_readable(["reward-strategy"])
        self.stackset.set_changeable(["reward-strategy"])
        # TODO might be dead code unless changes are algorithmic
        xyz = 123
        self.stackset.reset_access()
        return self

    def octahedron_test_site(self):
        exo = self
        self.stackset.set_readable(["stochasticity", "event", "site"])
        self.stackset.set_changeable([])
        evlast = self.stackset.peek("event")
        stoch = self.stackset.peek("stochasticity")
        if not evlast == "backoff-period":
            # We have been told to keep re/trying
            if (not stoch == None and stoch.octa == True):
                s = self.stackset.peek("site")
                s.classification = random.choice([True, False])
                if stoch.retries == True:
                    event = random.choice(
                        ["safety-tested", "test-safety-error"])
                else:
                    event = "safety-tested"

                if event == "test-safety-error":
                    stoch.n_octa = (stoch.n_octa + 1)

                exo.endo.update_event(event, None)
            else:
                assert False

        self.stackset.reset_access()
        return self

    def backoff(self):
        exo = self
        self.stackset.set_readable(["backoff-strategy"])
        self.stackset.set_changeable([])
        # Just the good old backoff mechanism
        # TODO add stochastic awareness for testing
        bs = self.stackset.peek("backoff-strategy")
        bs.retries = (bs.retries + 1)
        delay_ms = (bs.delay_ms * bs.scale_factor)
        if delay_ms > bs.max_delay_ms:
            self.endo.update_event("backoff-period", None)
        else:
            bs.delay_ms = delay_ms

        self.stackset.reset_access()
        return self

    def backoff_reset(self):
        exo = self
        self.stackset.set_readable(["backoff-strategy"])
        self.stackset.set_changeable([])
        # TODO stochastic
        bs = self.stackset.peek("backoff-strategy")
        bs.retries = 0
        bs.delay_ms = bs.min_delay_ms
        self.stackset.reset_access()
        return self

    def delay_in_range(self):
        exo = self
        self.stackset.set_readable(["backoff-strategy"])
        self.stackset.set_changeable(["boolean"])
        bs = self.stackset.peek("backoff-strategy")
        delay = bs.delay_ms
        mind = bs.min_delay_ms
        maxd = bs.max_delay_ms
        in_range = (delay >= mind and delay <= maxd)
        self.stackset.push("boolean", in_range)
        self.stackset.reset_access()
        return self

    def backoff_is_reset(self):
        exo = self
        self.stackset.set_readable(["backoff-strategy"])
        self.stackset.set_changeable(["boolean"])
        bs = self.stackset.peek("backoff-strategy")
        if not bs == None:
            is_reset = bs.delay_ms == bs.min_delay_ms
            self.stackset.push("boolean", is_reset)
        else:
            self.stackset.push("boolean", True)

        self.stackset.reset_access()
        return self

    def randomness_zero_one(self):
        exo = self
        self.stackset.set_readable(["backoff-strategy"])
        self.stackset.set_changeable(["boolean"])
        bs = self.stackset.peek("backoff-strategy")
        randomness = bs.randomness
        minr = 0
        maxr = 1
        in_range = (randomness >= minr and randomness <= maxr)
        self.stackset.push("boolean", in_range)
        self.stackset.reset_access()
        return self

    def valid_response_status(self):
        exo = self
        self.stackset.set_readable(["response"])
        self.stackset.set_changeable(["boolean"])
        r = self.stackset.peek("response")
        s = r.status
        # valid statuses -- 402 may be especially relevant for us
        valid_status = [200, 201, 202, 401, 402, 404, 409, 500, 501]
        b = is_member(s, valid_status)
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def valid_response_body(self):
        exo = self
        self.stackset.set_readable(["context", "response"])
        self.stackset.set_changeable(["boolean"])
        r = self.stackset.peek("response")
        ctx = self.stackset.peek("context")
        bod = r.body
        s = r.status
        b = True
        # We make sure that the response matches the status and the context
        if ctx.event == "public-galactus-account-create":
            # Should return the API Key
            if s == 201:
                b = (b and not bod == None)
                b = (b and key_response_sane(bod))
            elif s == 409:
                # Should return error-list
                # We handle form-validation at fapi-layer, but here we validate conflicts
                b = (b and not bod == None)
            else:
                assert False

        elif ctx.event == "public-galactus-account-destroy":
            # Should return public key
            if (s == 200 or s == 201 or s == 404 or s == 401):
                b = (b and not bod == None)
                b = (b and key_response_sane(bod))
                b = (b and bod["key"] == pub_key)
            elif s == 500:
                # Should return error-list
                # We handle form-validation at fapi-layer, but here we validate conflicts
                b = (b and not bod == None)
            else:
                assert False

        elif ctx.event == "public-galactus-account-login":
            # Should return API key and email and username
            if (s == 200 or s == 201):
                b = (b and not bod == None)
                b = (b and login_response_sane(bod))
            elif s == 401:
                # Bad credentials
                b = (b and not bod == None)
                b = (b and pub_key_response_sane(bod))
            else:
                assert False

        elif ctx.event == "public-galactus-account-logout":
            # Should return public key
            if (s == 200 or s == 201):
                b = (b and not bod == None)
                b = (b and pub_key_response_sane(bod))
            elif s == 401:
                # No such key
                b = (b and not bod == None)
                b = (b and pub_key_response_sane(bod))
            else:
                assert False

        elif ctx.event == "public-galactus-account-get":
            # Should return public info about galactus account or non-existence
            assert False
        elif ctx.event == "public-site-safe":
            b = (b and not bod == None)
            b = (b and malicious_response_sane(bod))

        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def stochasticity_non_zero_truth(self):
        exo = self
        self.stackset.set_readable(["stochasticity"])
        self.stackset.set_changeable([])
        s = self.stackset.peek("stochasticity")
        if not s.store:
            assert s.n_store == 0
        elif not s.load:
            assert s.n_load == 0
        elif not s.octa:
            assert s.n_octa == 0
        elif not s.azero:
            assert s.n_azero == 0
        elif not s.price:
            assert s.n_price == 0
        elif not s.retries:
            # TODO the idea is to guarantee that under stochastic conditions, retries eventually always succeed
            assert s.n_retries == 0

        self.stackset.reset_access()
        return self

    def respond(self):
        exo = self
        self.stackset.set_readable([
            "galactus-account", "response", "leaderboard", "reward-strategy",
            "ilock-policy", "site", "context"
        ])
        self.stackset.set_changeable([])
        ctx = self.stackset.peek("context")
        res = self.stackset.peek("response")
        if ctx.event == "public-galactus-account-create":
            if res.status == 500:
                res.body = {"message": "internal error"}
            elif res.status == 201:
                ga = self.stackset.peek("galactus-account")
                res.body = {"key": ga.api_key}
            elif res.status == 409:
                res.body = {"message": "account already exists"}

        elif ctx.event == "public-galactus-account-destroy":
            if res.status == 500:
                res.body = {"key": pub_key}
            elif res.status == 201:
                res.body = {"key": pub_key}
                # Override default status from the `changes-commited -> ready` transition
                res.status = 200
            elif res.status == 404:
                # Maybe add message
                # Are we giving away too much information by distinguishing 404 from 401?
                res.body = {"key": pub_key}
            elif res.status == 401:
                # Maybe add message
                res.body = {"key": pub_key}
            else:
                assert False

        elif ctx.event == "public-galactus-account-login":
            ga = self.stackset.peek("galactus-account")
            if res.status == 500:
                res.body = {"key": pub_key}
            elif ga == None:
                # TODO bad password, return public-key
                res.body = {"key": pub_key}
                res.status = 401
            elif not ga == None:
                if res.status == 401:
                    # Account was not found
                    res.body = {"key": pub_key}
                elif (res.status == 201 or res.status == 200):
                    # TODO password matches, return api-key
                    res.body = {
                        "key": ga.api_key,
                        "username": ga.username,
                        "email": ga.email
                    }
                    res.status = 200

        elif ctx.event == "public-galactus-account-logout":
            ga = self.stackset.peek("galactus-account")
            if res.status == 500:
                res.body = {"key": pub_key}
            elif ga == None:
                # TODO bad password, return public-key
                res.status = 401
                res.body = {"key": pub_key}
            elif not ga == None:
                if res.status == 401:
                    # Account was not found
                    res.body = {"key": pub_key}
                elif (res.status == 201 or res.status == 200):
                    # Account found, return pub-key
                    res.body = {"key": pub_key}
                    res.status = 200

        elif ctx.event == "public-site-safe":
            s = self.stackset.peek("site")
            if s.classification == None:
                res.status = 500
                # We got here because our octahedron requests failed
                # Instead of obscuring this, we let the client decide how to present this
                res.body = {"malicious": "unknown"}
            elif res.status == 500:
                # We got here because something else failed (i.e. status is already 500)
                # We reflect this in our status, but return the classification anyway
                res.body = {"malicious": s.classification}
            else:
                res.status = 200
                res.body = {"malicious": s.classification}

        else:
            assert False

        # Doing this triggers the response tests -- helps if accidentally bypass the above if-tree because of unhandled status-code
        res.locked = True
        self.stackset.reset_access()
        return self


exo = Exo()


# FAPI app
def validate_password_common(password):
    l = len(password)
    # TODO validate character set
    if l < 8:
        raise ValueError("password too short")

    return password


def validate_username_common(username):
    l = len(username)
    # TODO validate character set
    if l < 6:
        raise ValueError("username too short")

    return username


def validate_url_common(url):
    l = len(url)
    # TODO validate character set
    if l < 1:
        raise ValueError("url too short")

    return url


class UserRegistration(BaseModel):
    address: str
    email: str
    key: str
    password: str
    referrer: str
    terms_of_service: bool
    united_states: bool
    username: str

    @validator("password")
    def validate_password(cls, password):
        return validate_password_common(password)

    @validator("username")
    def validate_username(cls, username):
        return validate_username_common(username)


class SiteSafety(BaseModel):
    url: str
    key: str

    @validator("url")
    def validate_url(cls, url):
        return validate_url_common(password)


class ApiKey(BaseModel):
    key: str


class UserCreds(BaseModel):
    key: str
    username: str
    email: str


class SafetyResponse(BaseModel):
    malicious: Any


class UserDeletion(BaseModel):
    password: str
    confirm: bool
    username: str

    @validator("password")
    def validate_password(cls, password):
        return validate_password_common(password)

    @validator("username")
    def validate_username(cls, username):
        return validate_username_common(username)


class UserLogin(BaseModel):
    password: str
    email: str
    username: str

    @validator("password")
    def validate_password(cls, password):
        return validate_password_common(password)

    @validator("username")
    def validate_username(cls, username):
        return validate_username_common(username)


class UserLogout(BaseModel):
    key: str
    username: str

    @validator("username")
    def validate_username(cls, username):
        return validate_username_common(username)


endo = Endo()
endo.initialize_machine()
exo.set_endo(endo)
endo.send("ignite")
if (unit_test_mode == True and galactus_test_mode == True):
    fuzz_machine = fuzzer.TestCase
    unittest.main()

app = fapi.FastAPI()


@app.exception_handler(fapi.exceptions.RequestValidationError)
@app.exception_handler(fapi.exceptions.ValidationError)
def validation_exception_handler(req, exc):
    exc_json = json.loads(exc.json())
    res = {"message": [], "data": None}
    res_msg = res["message"]
    for e in exc_json:
        loc_ls = e["loc"]
        msg = (loc_ls[-1] + f" {e['msg']}")
        res_msg.append(msg)

    return JSONResponse(res, status_code=422)


alt_create_responses = {"409": {"message": "account already exists"}}


@app.post("/user-create", responses=alt_create_responses)
def http_user_create(user_reg: UserRegistration,
                     res_bptr: fapi.Response) -> ApiKey:
    username = user_reg.username
    email = user_reg.email
    password = user_reg.password
    exo.galactus_account_create(username=username,
                                unsalted_password=password,
                                email=email,
                                api_key=pub_key)
    try:
        endo.send("public-galactus-account-create")

    except Exception as e:
        endo.reset_machine()
        endo.send("ignite")
        logging.error("Caught internal error", exc_info=True)
        response = {"error": e}
        res_bptr.status_code = 500
        return response

    rsp_ls = endo.stackset.stacks["response"]
    rsp = rsp_ls[0]
    if rsp.status == 201:
        new_key = dict_get(rsp.body, "key")
        response = ApiKey(key=new_key)
    elif rsp.status == 409:
        response = JSONResponse(status_code=rsp.status, content=rsp.body)
    else:
        assert False

    res_bptr.status_code = rsp.status
    return response


alt_delete_responses = {
    "401": {
        "message": "bad credentials"
    },
    "404": {
        "message": "no such account"
    }
}


@app.post("/user-delete", responses=alt_delete_responses)
def http_user_delete(user_reg: UserDeletion,
                     res_bptr: fapi.Response) -> ApiKey:
    username = user_reg.username
    confirm = user_reg.confirm
    password = user_reg.password
    exo.galactus_account_create(username=username,
                                unsalted_password=password,
                                api_key=pub_key)
    try:
        endo.send("public-galactus-account-destroy")

    except Exception as e:
        endo.reset_machine()
        endo.send("ignite")
        logging.error("Caught internal error", exc_info=True)
        response = {"error": e}
        res_bptr.status_code = 500
        return response

    rsp_ls = endo.stackset.stacks["response"]
    rsp = rsp_ls[0]
    new_key = dict_get(rsp.body, "key")
    res_bptr.status_code = rsp.status
    response = ApiKey(key=new_key)
    return response


alt_login_responses = {"401": {"message": "bad credentials"}}


@app.post("/user-login", responses=alt_login_responses)
def http_user_login(user_li: UserLogin, res_bptr: fapi.Response) -> UserCreds:
    username = user_li.username
    email = user_li.email
    password = user_li.password
    exo.galactus_account_create(username=username,
                                api_key=pub_key,
                                unsalted_password=password)
    try:
        endo.send("public-galactus-account-login")

    except Exception as e:
        endo.reset_machine()
        endo.send("ignite")
        logging.error("Caught internal error", exc_info=True)
        response = {"error": e}
        res_bptr.status_code = 500
        return response

    rsp_ls = endo.stackset.stacks["response"]
    rsp = rsp_ls[0]
    res_bptr.status_code = rsp.status
    new_key = dict_get(rsp.body, "key")
    email = dict_get(rsp.body, "email")
    username = dict_get(rsp.body, "username")
    response = UserCreds(username=username, email=email, key=new_key)
    return response


alt_logout_responses = {"401": {"message": "bad credentials"}}


@app.post("/user-logout", responses=alt_logout_responses)
def http_user_logout(user_lo: UserLogout, res_bptr: fapi.Response) -> ApiKey:
    username = user_lo.username
    key = user_lo.key
    exo.galactus_account_create(username=username,
                                api_key=key,
                                salted_password='placeholder')
    try:
        endo.send("public-galactus-account-logout")

    except Exception as e:
        endo.reset_machine()
        endo.send("ignite")
        logging.error("Caught internal error", exc_info=True)
        response = {"error": e}
        res_bptr.status_code = 500
        return response

    rsp_ls = endo.stackset.stacks["response"]
    rsp = rsp_ls[0]
    res_bptr.status_code = rsp.status
    response = ApiKey(key=pub_key)
    return response


@app.post("/malicious_p")
@app.post("/malicious-p")
def http_malicious_p(site_safety: SiteSafety,
                     res_bptr: fapi.Response) -> SafetyResponse:
    url = site_safety.url
    key = site_safety.key
    if len(key) == 0:
        key = pub_key

    if len(url) > 256:
        # Truncate all urls to 256 bytes
        url = url[:256]

    exo.galactus_account_create(username='placeholder',
                                api_key=key,
                                salted_password='placeholder')
    exo.site_create(url=url)
    try:
        endo.send("public-site-safe")

    except Exception as e:
        endo.reset_machine()
        endo.send("ignite")
        logging.error("Caught internal error", exc_info=True)
        response = {"error": e}
        res_bptr.status_code = 500
        return response

    rsp_ls = endo.stackset.stacks["response"]
    rsp = rsp_ls[0]
    res_bptr.status_code = rsp.status
    mal = dict_get(rsp.body, "malicious")
    response = SafetyResponse(malicious=mal)
    return response


# TODO define verb wallet_as_load
