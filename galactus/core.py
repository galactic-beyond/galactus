import random as random
import datetime as datetime
import sqlalchemy as sql
from sqlalchemy import exc
import hypothesis as hyp
from hypothesis.provisional import domains, urls
from hypothesis import given
from operator import itemgetter
import fastapi as fapi

# Main Test Switch
galactus_test_mode = True
# Initialize Database Tables
db_path_main = "sqlite+pysqlite:///:memory:"
db_path_logs = "sqlite+pysqlite:///:memory:"
db_engine_main = sql.create_engine(db_path_main)
db_engine_logs = sql.create_engine(db_path_logs)
db_metadata_logs = sql.MetaData()
db_metadata_main = sql.MetaData()
log_table = sql.Table("galactus_logs", db_metadata_logs,
                      sql.Column("ctx_event", sql.String),
                      sql.Column("success", sql.Boolean),
                      sql.Column("begin_time", sql.DateTime),
                      sql.Column("end_time", sql.DateTime),
                      sql.Column("error_type", sql.String),
                      sql.Column("error_msg", sql.String))
heatmap_table = sql.Table("galactus_heatmap_logs", db_metadata_logs,
                          sql.Column("write_time", sql.DateTime),
                          sql.Column("src", sql.String),
                          sql.Column("dst", sql.String),
                          sql.Column("heat", sql.Integer))
deleted_galactus_account_table = sql.Table(
    "deleted_account", db_metadata_main,
    sql.Column("username", sql.String, primary_key=True),
    sql.Column("registration_date", sql.DateTime),
    sql.Column("deletion_date", sql.DateTime))
galactus_account_table = sql.Table(
    "galactus_account", db_metadata_main,
    sql.Column("username", sql.String, primary_key=True),
    sql.Column("salted_password", sql.String),
    sql.Column("wallet_id", sql.String),
    sql.Column("wallet_confirmed", sql.Boolean),
    sql.Column("tokens_deposited", sql.Integer),
    sql.Column("tokens_deducted", sql.Integer),
    sql.Column("tokens_earned", sql.Integer),
    sql.Column("tokens_earned-total", sql.Integer),
    sql.Column("lookups_total", sql.Integer),
    sql.Column("lookups_new", sql.Integer), sql.Column("malicious",
                                                       sql.Integer),
    sql.Column("unique", sql.Integer), sql.Column("flags", sql.Integer),
    sql.Column("unlocks", sql.Integer),
    sql.Column("unlocks_confirmed", sql.Integer),
    sql.Column("registration-date", sql.DateTime),
    sql.Column("referred", sql.Integer), sql.Column("referrer", sql.String),
    sql.Column("api_key", sql.String),
    sql.Column("api_key_expiration", sql.DateTime))
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
stochastify_octahedron = True
stochastify_azero = True
stochastify_price_oracle = True
stochastified_retries_succeed = True
if galactus_test_mode == True:
    db_metadata_main.drop_all(db_engine_main)
    db_metadata_logs.drop_all(db_engine_logs)

db_metadata_main.create_all(db_engine_main)
db_metadata_logs.create_all(db_engine_logs)
# Generators
hyp_email_strat = hyp.strategies.emails()
gen_email_list = []
gen_email_list_used = []


@given(hyp_email_strat)
def gen_email_populate(email):
    gen_email_list.append(email)


if galactus_test_mode == True:
    gen_email_populate()
    gen_email_list = list(set(gen_email_list))


def gen_email():
    r = random.choice(gen_email_list)
    gen_email_list.remove(r)
    gen_email_list_used.append(r)
    return r


hyp_url_strat = urls()
gen_url_list = []
gen_url_list_used = []


@given(hyp_url_strat)
def gen_url_populate(url):
    gen_url_list.append(url)


if galactus_test_mode == True:
    gen_url_populate()
    gen_url_list = list(set(gen_url_list))


def gen_url():
    r = random.choice(gen_url_list)
    gen_url_list.remove(r)
    gen_url_list_used.append(r)
    return r


hyp_domain_strat = domains()
gen_domain_list = []
gen_domain_list_used = []


@given(hyp_domain_strat)
def gen_domain_populate(domain):
    gen_domain_list.append(domain)


if galactus_test_mode == True:
    gen_domain_populate()
    gen_domain_list = list(set(gen_domain_list))


def gen_domain():
    r = random.choice(gen_domain_list)
    gen_domain_list.remove(r)
    gen_domain_list_used.append(r)
    return r


hyp_uuid_strat = hyp.strategies.uuids()
gen_uuid_list = []
gen_uuid_list_used = []


@given(hyp_uuid_strat)
def gen_uuid_populate(uuid):
    gen_uuid_list.append(uuid)


if galactus_test_mode == True:
    gen_uuid_populate()
    gen_uuid_list = list(set(gen_uuid_list))


def gen_uuid():
    r = random.choice(gen_uuid_list)
    gen_uuid_list.remove(r)
    gen_uuid_list_used.append(r)
    return r


hyp_username_strat = hyp.strategies.from_regex(regex='[A-Za-z0-9]+',
                                               fullmatch=True)
gen_username_list = []
gen_username_list_used = []


@given(hyp_username_strat)
def gen_username_populate(username):
    gen_username_list.append(username)


if galactus_test_mode == True:
    gen_username_populate()
    gen_username_list = list(set(gen_username_list))


def gen_username():
    r = random.choice(gen_username_list)
    gen_username_list.remove(r)
    gen_username_list_used.append(r)
    return r


# Generate objects and pushes them onto stack
def generate_unique_valid_account(exo):
    email = gen_email()
    password = "password123"
    username = gen_username()
    key = gen_uuid()
    exo.galactus_account_create(username=username,
                                unsalted_password=password,
                                email=email,
                                api_key=key)


def generate_unique_invalid_account(exo):
    email = gen_email()
    assert False


def generate_duplicate_account(exo):
    assert False


def generate_safe_site(exo):
    assert False


def generate_unsafe_site(exo):
    assert False


def run_program(exo):
    endo = Endo()
    endo.ticker_max = 3
    endo.initialize_machine()
    exo.set_endo(endo)
    msg = "hello world"
    print(msg)
    ns = endo.get_next_states()
    print(ns)
    hm = endo.heatmap_to_list()
    print(hm)
    endo.send("ignite")
    hm = endo.heatmap_to_list()
    print(hm)
    gas = endo.stackset.stacks["galactus-account"]
    print(gas)
    generate_unique_valid_account(exo)
    print(gas)
    print("creating")
    endo.send("public-galactus-account-create")
    ns = endo.get_next_states()
    print(ns)
    hm = endo.heatmap_to_list(sort_order="hotness")
    print(hm)


def is_member(elem, ls):
    for i in ls:
        if i == elem:
            return True

    return False


class paging_control:
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class context:
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class response:
    _exo = None
    response = ""
    status_id = 200

    def __init__(self, _exo, response="", status_id=200):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.response = response
        self.status_id = status_id
        self.__dict__["__constructed"] = True
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("response", self)
        (exo.valid_response_status().verify())
        exo.stackset.pop_unsafe("response")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class backoff_strategy:
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class db_load_query:
    _exo = None
    q = None

    def __init__(self, _exo, q=None):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.q = q
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class db_store_query:
    _exo = None
    q = None

    def __init__(self, _exo, q=None):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.q = q
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class db_error:
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class blockchain_error:
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class input_error:
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class octahedron_error:
    _exo = None
    e = ""

    def __init__(self, _exo, e=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.e = e
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class ilock_policy:
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class octa_verdict:
    _exo = None
    safe = False

    def __init__(self, _exo, safe=False):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.safe = safe
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class site:
    _exo = None
    url = ""
    flags = 0
    unlocks = 0
    visits = 0
    stake_state = ""
    classification = ""

    def __init__(self,
                 _exo,
                 url="",
                 flags=0,
                 unlocks=0,
                 visits=0,
                 stake_state="",
                 classification=""):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.url = url
        self.flags = flags
        self.unlocks = unlocks
        self.visits = visits
        self.stake_state = stake_state
        self.classification = classification
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class allow_block_list_item:
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class deleted_galactus_account:
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class galactus_account:
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
    flags = 0
    unique = 0
    malicious = 0
    lookups_new = 0
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
                 flags=0,
                 unique=0,
                 malicious=0,
                 lookups_new=0,
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
        self.flags = flags
        self.unique = unique
        self.malicious = malicious
        self.lookups_new = lookups_new
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
        return

    def __assert__(self):
        if not self.__dict__["__constructed"] == True:
            return

        exo = self._exo
        r_snap = exo.stackset.readable
        c_snap = exo.stackset.changeable
        exo.stackset.push_unsafe("galactus-account", self)
        (exo.have_wallet_id().verify())
        (exo.galactus_account_is_locked().
         have_either_salted_or_unsalted_password().guarded_verify())
        (exo.have_username().verify())
        exo.stackset.pop_unsafe("galactus-account")
        exo.stackset.readable = r_snap
        exo.stackset.changeable = c_snap
        return

    def __setattr__(self, name, value):
        self.__dict__[f"{name}"] = value
        self.__assert__()
        return

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class leaderboard:
    _exo = None
    dummy = 0

    def __init__(self, _exo, dummy=0):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.dummy = dummy
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


class reward_strategy:
    _exo = None
    dummy = 0

    def __init__(self, _exo, dummy=0):
        self.__dict__["__constructed"] = False
        self._exo = _exo
        self.dummy = dummy
        self.__dict__["__constructed"] = True
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

    def __getattr__(self, name):
        self.__assert__()
        return self.__dict__[f"{name}"]


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
        dict_put(stacks, "site", [])
        dict_put(stacks, "leaderboard", [])
        dict_put(stacks, "paging-control", [])
        dict_put(stacks, "context", [])
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

    def peek_n(self, stackname, n):
        allowed = is_member(stackname, self.readable)
        assert allowed

        ret = None
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


def pre_verify():
    if galactus_test_mode == True:
        # ready-contextualized
        (exo.state_create(name="ready").prev_state_is().context_empty().is_not(
        ).guarded_verify())
        # loaded-config
        (exo.state_create(name="ready").state_is().ilock_policy_empty().is_not(
        ).guarded_verify())
        # store-query-present-retry
        (exo.state_create(name="galactus-store-retry").next_state_is().
         db_store_query_empty().is_not().guarded_verify())
        # load-query-present-retry
        (exo.state_create(name="galactus-store-retry").next_state_is().
         db_load_query_empty().is_not().guarded_verify())
        # account-regdate-context-matches-try
        (exo.state_create(
            name="galactus-store-try").next_state_is().context_create(
                event="public-galactus-account-create").context_is().andify().
         account_regdate_after_context_timestamp().guarded_verify())
        # account-regdate-context-matches-retry
        (exo.state_create(
            name="galactus-store-retry").next_state_is().context_create(
                event="public-galactus-account-create").context_is().andify().
         account_regdate_after_context_timestamp().guarded_verify())


def post_verify():
    if galactus_test_mode == True:
        # respond-on-ready
        (exo.state_create(name="ready").next_state_is().state_create(
            name="begin-here").state_is().is_not().andify().response_empty().
         is_not().guarded_verify())
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
        (exo.state_create(name="galactus-store-try").next_state_is().
         db_store_query_empty().is_not().guarded_verify())
        # load-query-present-try
        (exo.state_create(name="galactus-store-try").next_state_is().
         db_load_query_empty().is_not().guarded_verify())
        # ready-empty-site
        (exo.state_create(
            name="ready").next_state_is().site_empty().guarded_verify())
        # ready-empty-backoff
        (exo.state_create(name="ready").next_state_is().backoff_strategy_empty(
        ).is_not().guarded_verify())


class Endo:
    stackset = StackSet()
    exo = {}
    state = "begin-here"
    wait_states = ["ready", "panic"]
    event = None
    ev_up = 0
    transitions = {}
    transition_code = {}
    valid_events = {}
    eventsets = {}
    rev_eventsets = {}
    heatmap = {}
    ticker = 0
    ticker_max = 0

    def update_event(self, event, eventset):
        self.stackset.set_changeable(["event", "prev-event", "eventset"])
        pe = self.stackset.pop("event")
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

        dest = dict_2get(self.transitions, self.state, self.event)
        dest_always = dict_2get(self.transitions, self.state, "@always")
        eventsets = dict_get(self.eventsets, self.event)
        self.ticker = (self.ticker + 1)
        eventset = None
        if not eventsets == None:
            if len(eventsets) == 1:
                eventset = eventset[0]
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
        self.add_many_to_event_set(
            "@conflict", ["galactus-account-exists", "wallet-in-use"])
        self.add_many_to_event_set("@public-mutate", [
            "public-galactus-account-create",
            "public-galactus-account-destroy", "public-wallet-add",
            "public-site-unlock", "public-site-flag"
        ])

        endo.add_transition("begin-here", "ready", "ignite")

        def begin_here_ready_ignite(endo):
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
                  begin_here_ready_ignite)

        endo.add_transition("ready", "ready", "hello")

        def ready_ready_hello(endo):
            pre_verify()
            endo.event = None
            (exo.string_create(val="hi"))
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "hello", ready_ready_hello)

        endo.add_transition("ready", "galactus-load-try", "@public-mutate")

        def ready_galactus_load_try_set_public_mutate(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "public-galactus-account-create":
                (exo.contextualize().galactus_account_regdatify().
                 galactus_account_name_as_load().data_load())
            elif br_event == "public-galactus-account-destroy":
                (exo.contextualize().galactus_account_name_as_load().data_load(
                ))
            elif br_event == "public-wallet-add":
                (exo.contextualize().wallet_as_load().data_load())
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

        dict_2put(endo.transition_code, "ready", "@public-mutate",
                  ready_galactus_load_try_set_public_mutate)

        endo.add_transition("ready", "ready", "invalid-input")

        def ready_ready_invalid_input(endo):
            pre_verify()
            endo.event = None
            (exo.respond())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "invalid-input",
                  ready_ready_invalid_input)

        endo.add_transition("ready", "galactus-store-try", "no-policy-stored")

        def ready_galactus_store_try_no_policy_stored(endo):
            pre_verify()
            endo.event = None
            (exo.ilock_policy_as_store().data_store())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "no-policy-stored",
                  ready_galactus_store_try_no_policy_stored)

        endo.add_transition("ready", "panic", "multiple-policies")

        def ready_panic_multiple_policies(endo):
            pre_verify()
            endo.event = None
            (exo.harakiri())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "multiple-policies",
                  ready_panic_multiple_policies)

        endo.add_transition("ready", "galactus-load-try",
                            "load-reward-strategy")

        def ready_galactus_load_try_load_reward_strategy(endo):
            pre_verify()
            endo.event = None
            (exo.contextualize().load_reward_strategy_table())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "load-reward-strategy",
                  ready_galactus_load_try_load_reward_strategy)

        endo.add_transition("site-flag-try", "stakeable-pending",
                            "site-reachable")

        def site_flag_try_stakeable_pending_site_reachable(endo):
            pre_verify()
            endo.event = None
            (exo.stakeable_pend())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "site-flag-try", "site-reachable",
                  site_flag_try_stakeable_pending_site_reachable)

        endo.add_transition("site-unlock-try", "stakeable-pending",
                            "site-reachable")

        def site_unlock_try_stakeable_pending_site_reachable(endo):
            pre_verify()
            # TODO
            assert False

            post_verify()
            return

        dict_2put(endo.transition_code, "site-unlock-try", "site-reachable",
                  site_unlock_try_stakeable_pending_site_reachable)

        endo.add_transition("stakeable-pending", "galactus-store-try",
                            "@always")

        def stakeable_pending_galactus_store_try_set_always(endo):
            pre_verify()
            endo.event = None
            (exo.stakeable_as_store().data_store())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "stakeable-pending", "@always",
                  stakeable_pending_galactus_store_try_set_always)

        endo.add_transition("stakeable-shelved", "galactus-store-try",
                            "@always")

        def stakeable_shelved_galactus_store_try_set_always(endo):
            pre_verify()
            # TODO
            assert False

            post_verify()
            return

        dict_2put(endo.transition_code, "stakeable-shelved", "@always",
                  stakeable_shelved_galactus_store_try_set_always)

        endo.add_transition("site-flag-try", "stakeable-shelved",
                            "site-unreachable")

        def site_flag_try_stakeable_shelved_site_unreachable(endo):
            pre_verify()
            endo.event = None
            (exo.stakeable_shelve())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "site-flag-try", "site-unreachable",
                  site_flag_try_stakeable_shelved_site_unreachable)

        endo.add_transition("site-unlock-try", "stakeable-shelved",
                            "site-unreachable")

        def site_unlock_try_stakeable_shelved_site_unreachable(endo):
            pre_verify()
            # TODO
            assert False

            post_verify()
            return

        dict_2put(endo.transition_code, "site-unlock-try", "site-unreachable",
                  site_unlock_try_stakeable_shelved_site_unreachable)

        endo.add_transition("ready", "galactus-load-try", "@public-fetch")

        def ready_galactus_load_try_set_public_fetch(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "public-stakeables-list":
                (exo.contextualize().stakeables_list().data_load())
            elif br_event == "public-stakeable-get":
                (exo.contextualize().stakeable_get().data_load())
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
                  ready_galactus_load_try_set_public_fetch)

        endo.add_transition("ready", "test-site-malicious", "public-site-safe")

        def ready_test_site_malicious_public_site_safe(endo):
            pre_verify()
            endo.event = None
            (exo.contextualize())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "ready", "public-site-safe",
                  ready_test_site_malicious_public_site_safe)

        endo.add_transition("test-site-malicious", "increment-user-balance",
                            "@always")

        def test_site_malicious_increment_user_balance_set_always(endo):
            pre_verify()
            # TODO
            assert False

            post_verify()
            return

        dict_2put(endo.transition_code, "test-site-malicious", "@always",
                  test_site_malicious_increment_user_balance_set_always)

        endo.add_transition("increment-user-balance", "galactus-store-try",
                            "@always")

        def increment_user_balance_galactus_store_try_set_always(endo):
            pre_verify()
            # TODO
            assert False

            post_verify()
            return

        dict_2put(endo.transition_code, "increment-user-balance", "@always",
                  increment_user_balance_galactus_store_try_set_always)

        endo.add_transition("ready", "galactus-store-try", "@admin-db-change")

        def ready_galactus_store_try_set_admin_db_change(endo):
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
                  ready_galactus_store_try_set_admin_db_change)

        endo.add_transition("galactus-load-try", "ready", "galactus-loaded")

        def galactus_load_try_ready_galactus_loaded(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().load_query_discard().stack_gc().respond())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-try", "galactus-loaded",
                  galactus_load_try_ready_galactus_loaded)

        endo.add_transition("galactus-load-try", "galactus-load-retry",
                            "galactus-load-error")

        def galactus_load_try_galactus_load_retry_galactus_load_error(endo):
            pre_verify()
            endo.event = None
            (exo.backoff().data_load())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-try",
                  "galactus-load-error",
                  galactus_load_try_galactus_load_retry_galactus_load_error)

        endo.add_transition("galactus-load-retry", "galactus-load-retry",
                            "galactus-load-error")

        def galactus_load_retry_galactus_load_retry_galactus_load_error(endo):
            pre_verify()
            endo.event = None
            (exo.backoff().data_load())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-retry",
                  "galactus-load-error",
                  galactus_load_retry_galactus_load_retry_galactus_load_error)

        endo.add_transition("galactus-load-retry", "ready", "galactus-loaded")

        def galactus_load_retry_ready_galactus_loaded(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().stack_gc())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-retry",
                  "galactus-loaded", galactus_load_retry_ready_galactus_loaded)

        endo.add_transition("galactus-load-retry", "notify-admin",
                            "backoff-period")

        def galactus_load_retry_notify_admin_backoff_period(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().load_query_discard().stack_gc())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-retry",
                  "backoff-period",
                  galactus_load_retry_notify_admin_backoff_period)

        endo.add_transition("galactus-store-try", "commit-changes",
                            "galactus-stored")

        def galactus_store_try_commit_changes_galactus_stored(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().store_query_discard().stack_gc())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-store-try",
                  "galactus-stored",
                  galactus_store_try_commit_changes_galactus_stored)

        endo.add_transition("galactus-store-try", "galactus-store-retry",
                            "galactus-store-error")

        def galactus_store_try_galactus_store_retry_galactus_store_error(endo):
            pre_verify()
            endo.event = None
            (exo.backoff().data_store())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-store-try", "galactus-store-error",
            galactus_store_try_galactus_store_retry_galactus_store_error)

        endo.add_transition("galactus-store-retry", "galactus-store-retry",
                            "galactus-store-error")

        def galactus_store_retry_galactus_store_retry_galactus_store_error(
                endo):
            pre_verify()
            endo.event = None
            (exo.backoff().data_store())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-store-retry",
            "galactus-store-error",
            galactus_store_retry_galactus_store_retry_galactus_store_error)

        endo.add_transition("galactus-store-retry", "commit-changes",
                            "galactus-stored")

        def galactus_store_retry_commit_changes_galactus_stored(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().stack_gc())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-store-retry",
                  "galactus-stored",
                  galactus_store_retry_commit_changes_galactus_stored)

        endo.add_transition("galactus-store-retry", "notify-admin",
                            "backoff-period")

        def galactus_store_retry_notify_admin_backoff_period(endo):
            pre_verify()
            endo.event = None
            (exo.backoff_reset().store_query_discard().stack_gc())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-store-retry",
                  "backoff-period",
                  galactus_store_retry_notify_admin_backoff_period)

        endo.add_transition("galactus-load-try", "ready", "@conflict")

        def galactus_load_try_ready_set_conflict(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "galactus-account-exists":
                (exo.respond())
            elif br_event == "wallet-in-use":
                (exo.respond())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-try", "@conflict",
                  galactus_load_try_ready_set_conflict)

        endo.add_transition("galactus-load-retry", "ready", "@conflict")

        def galactus_load_retry_ready_set_conflict(endo):
            pre_verify()
            endo.event = None
            self.stackset.set_readable(["event"])
            br_event = self.stackset.peek("event")
            self.stackset.reset_access()
            if br_event == "galactus-account-exists":
                (exo.respond())
            elif br_event == "wallet-in-use":
                (exo.respond())
            else:
                assert False

            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "galactus-load-retry", "@conflict",
                  galactus_load_retry_ready_set_conflict)

        endo.add_transition("galactus-load-try", "galactus-store-try",
                            "galactus-account-non-existent")

        def galactus_load_try_galactus_store_try_galactus_account_non_existent(
                endo):
            pre_verify()
            endo.event = None
            (exo.galactus_account_hashify_password().galactus_account_as_store(
            ).data_store())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-load-try",
            "galactus-account-non-existent",
            galactus_load_try_galactus_store_try_galactus_account_non_existent)

        endo.add_transition("galactus-load-retry", "galactus-store-try",
                            "galactus-account-non-existent")

        def galactus_load_retry_galactus_store_try_galactus_account_non_existent(
                endo):
            pre_verify()
            # TODO
            assert False

            post_verify()
            return

        dict_2put(
            endo.transition_code, "galactus-load-retry",
            "galactus-account-non-existent",
            galactus_load_retry_galactus_store_try_galactus_account_non_existent
        )

        endo.add_transition("notify-admin", "ready", "commited")

        def notify_admin_ready_commited(endo):
            pre_verify()
            endo.event = None
            (exo.context_log().respond())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "notify-admin", "commited",
                  notify_admin_ready_commited)

        endo.add_transition("commit-changes", "ready", "commited")

        def commit_changes_ready_commited(endo):
            pre_verify()
            endo.event = None
            (exo.context_log().respond())
            if endo.event == None:
                endo.update_event(None, None)

            post_verify()
            return

        dict_2put(endo.transition_code, "commit-changes", "commited",
                  commit_changes_ready_commited)


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
        l = len(self.stackset.stacks["galactus-account"])
        self.stackset.push("number", l)
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
                                flags=0,
                                unique=0,
                                malicious=0,
                                lookups_new=0,
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
            unlocks, flags, unique, malicious, lookups_new, lookups_total,
            tokens_earned_total, tokens_earned, tokens_deducted,
            tokens_deposited, wallet_confirmed, wallet_id, unsalted_password,
            salted_password, email, username)
        dstack = self.stackset.stacks["galactus-account"]
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
        l = len(self.stackset.stacks["site"])
        self.stackset.push("number", l)
        return self

    def site_create(self,
                    url="",
                    flags=0,
                    unlocks=0,
                    visits=0,
                    stake_state="",
                    classification=""):
        self.stackset.set_changeable(["site"])
        ret = site(self, url, flags, unlocks, visits, stake_state,
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
        l = len(self.stackset.stacks["leaderboard"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["paging-control"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["context"])
        self.stackset.push("number", l)
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

    def db_load_query_empty(self):
        self.stackset.set_readable(["db-load-query", "boolean"])
        self.stackset.set_changeable(["boolean"])
        slen = self.stackset.stack_len("db-load-query")
        self.stackset.push("boolean", slen == 0)
        self.stackset.reset_access()
        return self

    def db_load_query_length(self):
        l = len(self.stackset.stacks["db-load-query"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["db-store-query"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["ilock-policy"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["reward-strategy"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["response"])
        self.stackset.push("number", l)
        return self

    def response_create(self, response="", status_id=200):
        self.stackset.set_changeable(["response"])
        ret = response(self, response, status_id)
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
        l = len(self.stackset.stacks["octa-verdict"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["backoff-strategy"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["db-error"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["blockchain-error"])
        self.stackset.push("number", l)
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
        l = len(self.stackset.stacks["octahedron-error"])
        self.stackset.push("number", l)
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
        l = len(dict_get(self.stackset.stacks, "input-error"))
        return self

    def input_error_create(self, e=""):
        self.stackset.set_changeable(["input-error"])
        ret = input_error(self, e)
        ret._exo = exo
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
        self.stackset.set_changeable(["context"])
        assert self.stackset.stack_len("event") > 0

        ev = self.stackset.peek("event")
        ts = datetime.datetime.now()
        self.stackset.pop("context")
        self.context_create(event=ev, timestamp_start=ts)
        self.stackset.reset_access()
        return self

    def context_log(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable([])
        assert self.stackset.stack_len("context") > 0

        ctx = self.stackset.peek("context")
        ctx.timestamp_end = datetime.datetime.now()
        ctx.locked = True
        # TODO use db_engine_log to write context object
        self.stackset.reset_access()
        return self

    def context_is(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["boolean", "context"])
        assert self.stackset.stack_len("context") > 0

        ctx1 = self.stackset.peek("context")
        ctx2 = self.stackset.peek("context")
        if ctx2 == None:
            self.stackset.push("boolean", False)
            self.stackset.pop("context")
        else:
            b = ctx1.event == ctx2.event
            self.stackset.push("boolean", b)
            self.stackset.pop("context")

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
        self.stackset.set_readable(["context", "db-load-query"])
        self.stackset.set_changeable(
            ["db-error", "site", "leaderboard", "galactus-account"])
        assert self.stackset.stack_len("db-load-query") > 0

        assert self.stackset.stack_len("context") > 0

        dbq = self.stackset.peek("db-load-query")
        q = dbq.q
        ctx = self.stackset.peek("context")
        ev = ctx.event
        with db_engine_main.connect() as conn:
            if ev == "public-galactus-account-create":
                rows = conn.execute(q)
                row = rows.first()
                if not row == None:
                    self.endo.update_event("galactus-account-exists", None)
                elif row == None:
                    self.endo.update_event("galactus-account-non-existent",
                                           None)

            elif ev == "public-galactus-account-get":
                rows = conn.execute(q)
                row = rows.first()
                if row == None:
                    self.endo.update_event("galactus-account-non-existent",
                                           None)
                elif not row == None:
                    assert False

            elif (ev == "public-site-unlock" or ev == "public-site-flag"
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
                    self.endo.update_event("stakeable-non-existent", None)
                elif len(rows) > 0:
                    for r in rows:
                        xyz = 123
                        assert False

                    self.endo.update_event("stakeable-exists", None)

        self.stackset.reset_access()
        return self

    def data_store(self):
        exo = self
        self.stackset.set_readable(["context", "db-store-query"])
        self.stackset.set_changeable(["db-error"])
        assert self.stackset.stack_len("db-store-query") > 0

        dbq = self.stackset.peek("db-store-query")
        q = dbq.q
        try:
            with db_engine_main.connect() as conn:
                rows = conn.execute(q)

            self.endo.update_event("galactus-stored", None)

        except exc.SQLAlchemyError:
            assert False

        self.stackset.reset_access()
        return self

    def stack_gc(self):
        exo = self
        self.stackset.set_readable(["context"])
        self.stackset.set_changeable(["galactus-account"])
        ctx = self.stackset.peek("context")
        event = ctx.event
        if event == "public-galactus-account-create":
            self.stackset.pop("galactus-account")

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
        self.endo.update_event("commited", None)
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
        q = sql.select(galactus_account_table.c.api_key)
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

    def galactus_account_hashify_password(self):
        exo = self
        self.stackset.set_readable(["galactus-account"])
        self.stackset.set_changeable(["galactus-account"])
        ga = self.stackset.peek("galactus-account")
        ga.locked = False
        p = ga.salted_password
        ga.salted_password = ga.unsalted_password
        ga.unsalted_password = p
        ga.locked = True
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
        q = sql.insert(galactus_account_table)
        q = q.values(username=gaun, salted_password=gasp)
        exo.db_store_query_create(q=q)
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
        su = s.unlocks
        sf = s.flags
        su = s.url
        q = sql.insert(site_table)
        q = q.values(stake_state=ss, visits=sv, unlocks=su, flags=sf, url=su)
        exo.db_store_query_create(q=q)
        self.stackset.reset_access()
        return self

    def stakeable_as_load(self):
        exo = self
        self.stackset.set_readable(["site"])
        self.stackset.set_changeable(["db-load-query"])
        s = self.stackset.peek("site")
        su = s.url
        q = sql.select(site_table)
        q = q.values(url=su)
        exo.db_load_query_create(q=q)
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

    def stakeable_get(self):
        exo = self
        self.stackset.set_readable(["site", "page"])
        self.stackset.set_changeable(["site"])
        # TODO dead code and should be removed
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

    def backoff(self):
        exo = self
        self.stackset.set_readable(["backoff-strategy"])
        self.stackset.set_changeable([])
        # Just the good old backoff mechanism
        # TODO add stochastic awareness for testing
        bs = self.stackset.peek("backoff-strategy")
        bs.retries = (bs.retries + 1)
        bs.delay_ms = (bs.delay_ms * scale_factor)
        if bs.delay_ms > bs.max_delay_ms:
            self.endo.update_event("backoff-period", None)

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
        valid_status = [200, 201, 202, 401, 402, 404, 500, 501]
        b = is_member(s, valid_status)
        self.stackset.push("boolean", b)
        self.stackset.reset_access()
        return self

    def respond(self):
        exo = self
        self.stackset.set_readable([
            "leaderboard", "reward-strategy", "ilock-policy", "site", "context"
        ])
        self.stackset.set_changeable(["response"])
        res = fapi.Response()
        res.status = xxx
        res.response = xxx
        self.stackset.push("response", res)
        self.stackset.reset_access()
        return self

    # TODO define verb wallet-as-load


exo = Exo()
run_program(exo)
