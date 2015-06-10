import traceback
import threading
import socket
import time
import ssl

numeric_events = {
    b"001": b"welcome",
    b"002": b"yourhost",
    b"003": b"created",
    b"004": b"myinfo",
    b"005": b"featurelist",
    b"200": b"tracelink",
    b"201": b"traceconnecting",
    b"202": b"tracehandshake",
    b"203": b"traceunknown",
    b"204": b"traceoperator",
    b"205": b"traceuser",
    b"206": b"traceserver",
    b"207": b"traceservice",
    b"208": b"tracenewtype",
    b"209": b"traceclass",
    b"210": b"tracereconnect",
    b"211": b"statslinkinfo",
    b"212": b"statscommands",
    b"213": b"statscline",
    b"214": b"statsnline",
    b"215": b"statsiline",
    b"216": b"statskline",
    b"217": b"statsqline",
    b"218": b"statsyline",
    b"219": b"endofstats",
    b"221": b"umodeis",
    b"231": b"serviceinfo",
    b"232": b"endofservices",
    b"233": b"service",
    b"234": b"servlist",
    b"235": b"servlistend",
    b"241": b"statslline",
    b"242": b"statsuptime",
    b"243": b"statsoline",
    b"244": b"statshline",
    b"250": b"luserconns",
    b"251": b"luserclient",
    b"252": b"luserop",
    b"253": b"luserunknown",
    b"254": b"luserchannels",
    b"255": b"luserme",
    b"256": b"adminme",
    b"257": b"adminloc1",
    b"258": b"adminloc2",
    b"259": b"adminemail",
    b"261": b"tracelog",
    b"262": b"endoftrace",
    b"263": b"tryagain",
    b"265": b"n_local",
    b"266": b"n_global",
    b"300": b"none",
    b"301": b"away",
    b"302": b"userhost",
    b"303": b"ison",
    b"305": b"unaway",
    b"306": b"nowaway",
    b"311": b"whoisuser",
    b"312": b"whoisserver",
    b"313": b"whoisoperator",
    b"314": b"whowasuser",
    b"315": b"endofwho",
    b"316": b"whoischanop",
    b"317": b"whoisidle",
    b"318": b"endofwhois",
    b"319": b"whoischannels",
    b"321": b"liststart",
    b"322": b"list",
    b"323": b"listend",
    b"324": b"channelmodeis",
    b"329": b"channelcreate",
    b"331": b"notopic",
    b"332": b"currenttopic",
    b"333": b"topicinfo",
    b"341": b"inviting",
    b"342": b"summoning",
    b"346": b"invitelist",
    b"347": b"endofinvitelist",
    b"348": b"exceptlist",
    b"349": b"endofexceptlist",
    b"351": b"version",
    b"352": b"whoreply",
    b"353": b"namreply",
    b"354": b"whospcrpl",
    b"361": b"killdone",
    b"362": b"closing",
    b"363": b"closeend",
    b"364": b"links",
    b"365": b"endoflinks",
    b"366": b"endofnames",
    b"367": b"banlist",
    b"368": b"endofbanlist",
    b"369": b"endofwhowas",
    b"371": b"info",
    b"372": b"motd",
    b"373": b"infostart",
    b"374": b"endofinfo",
    b"375": b"motdstart",
    b"376": b"endofmotd",
    b"377": b"motd2",
    b"381": b"youreoper",
    b"382": b"rehashing",
    b"384": b"myportis",
    b"391": b"time",
    b"392": b"usersstart",
    b"393": b"users",
    b"394": b"endofusers",
    b"395": b"nousers",
    b"396": b"event_hosthidden",
    b"401": b"nosuchnick",
    b"402": b"nosuchserver",
    b"403": b"nosuchchannel",
    b"404": b"cannotsendtochan",
    b"405": b"toomanychannels",
    b"406": b"wasnosuchnick",
    b"407": b"toomanytargets",
    b"409": b"noorigin",
    b"411": b"norecipient",
    b"412": b"notexttosend",
    b"413": b"notoplevel",
    b"414": b"wildtoplevel",
    b"421": b"unknowncommand",
    b"422": b"nomotd",
    b"423": b"noadmininfo",
    b"424": b"fileerror",
    b"431": b"nonicknamegiven",
    b"432": b"erroneusnickname",
    b"433": b"nicknameinuse",
    b"436": b"nickcollision",
    b"437": b"unavailresource",
    b"441": b"usernotinchannel",
    b"442": b"notonchannel",
    b"443": b"useronchannel",
    b"444": b"nologin",
    b"445": b"summondisabled",
    b"446": b"usersdisabled",
    b"451": b"notregistered",
    b"461": b"needmoreparams",
    b"462": b"alreadyregistered",
    b"463": b"nopermforhost",
    b"464": b"passwdmismatch",
    b"465": b"yourebannedcreep",
    b"466": b"youwillbebanned",
    b"467": b"keyset",
    b"471": b"channelisfull",
    b"472": b"unknownmode",
    b"473": b"inviteonlychan",
    b"474": b"bannedfromchan",
    b"475": b"badchannelkey",
    b"476": b"badchanmask",
    b"477": b"nochanmodes",
    b"478": b"banlistfull",
    b"481": b"noprivileges",
    b"482": b"chanoprivsneeded",
    b"483": b"cantkillserver",
    b"484": b"restricted",
    b"485": b"uniqopprivsneeded",
    b"491": b"nooperhost",
    b"492": b"noservicehost",
    b"501": b"umodeunknownflag",
    b"502": b"usersdontmatch",
    b"728": b"quietlist",
    b"729": b"quietlistend",
}

def pick(arg, default):
    return default if arg is None else arg

def parse_command(element): # original code from oyoyo's parse_raw_irc_command
    parts = element.split()

    if parts[0].startswith(b":"):
        prefix = parts[0][1:]
        command = parts[1]
        rest = parts[2:]
    else:
        prefix = None
        command = parts[0]
        rest = parts[1:]

    if command.isdigit():
        command = numeric_events.get(command, command)

    command = command.decode("utf-8").lower()

    if rest[0].startswith(b":"):
        rest = [b" ".join(rest)[1:]]
    else:
        for i, arg in enumerate(rest):
            if arg.startswith(b":"):
                rest = rest[:i] + [b" ".join(rest[i:])[1:]]
                break

    return (prefix, command, rest)

def parse_nick(name):
    if "!" not in name:
        return (name, None, None)

    nick, rest = name.split("!")

    if "@" not in name:
        return (nick, rest, None)

    user, host = rest.split("@")

    return (nick, user, host)

Hooks = {}

class handler:
    """A decorator to get the commands."""

    def __init__(self, name):
        self.name = name
        self.func = None

        Hooks[name] = self

    def __call__(self, func):
        self.func = func
        return self.func

    def caller(self, *args):
        return self.func(*args)

# Adapted from http://code.activestate.com/recipes/511490-implementation-of-the-token-bucket-algorithm/
# original code by Duncan Fordyce
class TokenBucket:
    """An implementation of the token bucket algorithm.

    >>> bucket = TokenBucket(80, 0.5)
    >>> bucket.consume(1)
    """
    def __init__(self, tokens, fill_rate):
        self.capacity = float(tokens)
        self._tokens = float(tokens)
        self.fill_rate = float(fill_rate)
        self.timestamp = time.time()

    def consume(self, tokens=1):
        """Consume tokens from the bucket. Returns True if there were
        sufficient tokens otherwise False."""
        if tokens <= self.tokens:
            self._tokens -= tokens
            return True
        return False

    @property
    def tokens(self):
        now = time.time()
        if self._tokens < self.capacity:
            delta = self.fill_rate * (now - self.timestamp)
            self._tokens = min(self.capacity, self._tokens + delta)
        self.timestamp = now
        return self._tokens

class IRCClient:
    """Handle many connections to a server."""

    def __init__(self, *, nickname=None, ident=None, realname=None, address=None,
                          port=None, use_sasl=None, use_ssl=None, sasl_pass=None,
                          server_pass=None, sasl_name=None, threshold=None,
                          clients_count=None, connect_callback=None,
                          logger=None, is_fake_connection=None):

        self.logger = pick(logger, print)
        self.secondary_clients = {} # client -> threading lock for that client
        self.nick_mapping = {} # nick -> user manager instance it belongs to
        self.is_fake_connection = pick(is_fake_connection, False)

        if self.is_fake_connection:
            self.nickname = None
            self.ident = None
            self.realname = None
            self.address = None
            self.port = None
            self.use_sasl = None
            self.use_ssl = None
            self.sasl_pass = None
            self.server_pass = None
            self.sasl_name = None
            self.threshold = None
            self.clients_count = None
            self.connect_callback = None
            self.primary_lock = threading.RLock()
            self.primary_client = Client(logger=self.logger, is_fake_connection=True)

        elif nickname is None:
            raise RuntimeError("no nickname was specified on a non-fake connection")

        else:
            self.nickname = nickname
            self.ident = pick(ident, nickname)
            self.realname = pick(realname, nickname)
            self.address = pick(address, "127.0.0.1")
            self.port = pick(port, 6667)
            self.use_sasl = pick(use_sasl, False)
            self.use_ssl = pick(use_ssl, False)
            self.sasl_pass = pick(sasl_pass, "NOPASS")
            self.server_pass = server_pass
            self.sasl_name = pick(sasl_name, nickname)
            self.threshold = pick(threshold, 2)
            self.clients_count = pick(clients_count, 0) # this is the count of secondary clients allowed
            self.connect_callback = connect_callback
            self.primary_lock = threading.RLock()
            self.primary_client = Client(nickname=self.nickname,
                                         ident=self.ident,
                                         realname=self.realname,
                                         address=self.address,
                                         port=self.port,
                                         use_sasl=self.use_sasl,
                                         use_ssl=self.use_ssl,
                                         sasl_pass=self.sasl_pass,
                                         server_pass=self.server_pass,
                                         sasl_name=self.sasl_name,
                                         connect_callback=connect_callback,
                                         logger=self.logger,
                                         lock=self.primary_lock,
                                        )

        self.users = None

    def map_users(self, users): # 'users' is the list of joined players
        clients = {client: [] for client in self.secondary_clients}

        runner = iter(self.secondary_clients)
        for user in users:
            try:
                client = next(runner)
            except StopIteration:
                runner = iter(self.secondary_clients)
                client = next(runner)

            clients[client].append(user)

        self.users = clients

    def end_game(self):
        self.users = None

    def send_all(self, *args):
        with self.primary_lock:
            self.primary_client.send(*args)
        for client, lock in self.secondary_clients:
            with lock:
                client.send(*args)

    def msg(self, target, *data):
        if target.startswith("#"):
            with self.primary_lock:
                return self.primary_client.msg(target, *data)

        if self.users is not None: # game is going on
            for client in self.users:
                if target in self.users[client]:
                    with self.secondary_clients[client]:
                        return client.msg(target, *data)

        last_said = {x.lastsaid: x for x in self.secondary_clients}
        return last_said[max(last_said)].msg(target, *data)

    def notice(self, target, *data):
        if target.startswith("#"):
            with self.primary_lock:
                return self.primary_client.notice(target, *data)

        if self.users is not None:
            for client in self.users:
                if target in self.users[client]:
                    with self.secondary_clients[client]:
                        return client.notice(target, *data)

        last_said = {x.lastsaid: x for x in self.secondary_clients}
        return last_said[max(last_said)].notice(target, *data)

    def join(self, channel, pw=""):
        self.send_all("JOIN {0} :{1}".format(channel, pw))

    def part(self, channel, reason=""):
        self.send_all("PART {0} :{1}".format(channel, reason))

    def quit(self, reason=""):
        self.send_all("QUIT :{0}".format(reason))

    def mode(self, channel, *modes):
        with self.primary_lock:
            self.primary_client.send("MODE {0} :{1}".format(channel, " ".join(mode)))

    def nick(self, nickname):
        with self.primary_lock:
            self.primary_client.send("NICK {0}".format(nickname))

    def kick(self, channel, nick, reason=""):
        with self.primary_lock:
            self.primary_client.send("KICK {0} {1} :{2}".format(channel, nick, reason))

    def who(self, channel, params):
        with self.primary_lock:
            self.primary_client.send("WHO {0} :{1}".format(channel, params))

    def cap(self, *capabilities):
        self.send_all("CAP {0}".format(" ".join(capabilities)))

    def ns_identify(self, pw):
        with self.primary_lock:
            self.primary_client.msg("NickServ", "IDENTIFY", self.nickname, pw)

    def ns_ghost(self):
        with self.primary_lock:
            self.primary_client.msg("NickServ", "GHOST", self.nickname)

    def ns_release(self):
        with self.primary_lock:
            self.primary_client.msg("NickServ", "RELEASE", self.nickname)

    def ns_regain(self):
        with self.primary_lock:
            self.primary_client.msg("NickServ", "REGAIN", self.nickname)

    def start(self):
        if self.is_fake_connection:
            self.primary_client.start()
        else:
            threading.Thread(None, self.primary_client.start).start()

        num = self.clients_count
        i = 1
        while num:
            client = Client(nickname=self.nickname + str(i),
                            ident=self.ident,
                            realname=self.realname,
                            address=self.address,
                            port=self.port,
                            use_sasl=self.use_sasl,
                            use_ssl=self.use_ssl,
                            sasl_pass=self.sasl_pass,
                            server_pass=self.server_pass,
                            sasl_name=self.sasl_name,
                            connect_callback=self.connect_callback,
                            logger=self.logger,
                            lock=threading.RLock(),
                           )

            self.secondary_clients[client] = client.lock

            threading.Thread(None, client.start).start()

            num -= 1
            i += 1

class Client:
    """Basic IRC Client that handles one connection to a server."""

    def __init__(self, *, nickname=None, ident=None, realname=None, address=None,
                          port=None, use_sasl=None, use_ssl=None, sasl_pass=None,
                          server_pass=None, sasl_name=None, connect_callback=None,
                          lock=None, logger=None, is_fake_connection=None):

        self.is_fake_connection = pick(is_fake_connection, False)
        self.logger = pick(logger, print)

        if self.is_fake_connection:
            self.nickname = None
            self.ident = None
            self.realname = None
            self.address = None
            self.port = None
            self.use_sasl = None
            self.use_ssl = None
            self.sasl_pass = None
            self.server_pass = None
            self.sasl_name = None
            self.connect_callback = None
            self.lock = None
            self.socket = None
            self.tokenbucket = None

        elif nickname is None:
            raise RuntimeError("no nickname specified")

        elif lock is None:
            raise RuntimeError("must pass in a threading lock")

        else:
            self.nickname = nickname
            self.ident = pick(ident, self.nickname)
            self.realname = pick(realname, self.nickname)
            self.address = pick(address, "127.0.0.1")
            self.port = pick(port, 6667)
            self.use_sasl = pick(use_sasl, False)
            self.use_ssl = pick(use_ssl, False)
            self.sasl_pass = sasl_pass
            self.server_pass = server_pass
            self.sasl_name = pick(sasl_name, self.nickname)
            self.connect_callback = connect_callback
            self.lock = lock
            self.socket = socket.socket()
            self.tokenbucket = TokenBucket(4, 0.5)

            if self.use_ssl:
                self.socket = ssl.wrap_socket(self.socket)

        self._lastsaid = 0

    def send(self, *data):
        with self.lock:
            bytedata = [x.encode("utf-8") for x in data]
            self.logger("send    ---> {0}".format(" ".join(data))) # extra spaces to match up with 'receive'

            while self.tokenbucket and not self.tokenbucket.consume():
                time.sleep(0.2)
            if self.socket is not None:
                self.socket.send(b" ".join(bytedata) + b"\r\n")
            self._lastsaid = time.time()

    def _privmsg(self, target, *data, value="PRIVMSG"):
        for line in " ".join(data).splitlines():
            while line:
                extra = ""
                if len(line) > 380:
                    line, extra = line[:380], line[380:]
                self.send(value, target, ":{0}".format(line))
                line = extra

    def msg(self, target, *data):
        with self.lock:
            self._privmsg(target, *data)

    def notice(self, target, *data):
        with self.lock:
            self._privmsg(target, *data, value="NOTICE")

    def join(self, channel, pw=""):
        self.send("JOIN {0} :{1}".format(channel, pw))

    def part(self, channel, reason=""):
        self.send("PART {0} :{1}".format(channel, reason))

    def quit(self, reason=""):
        self.send("QUIT :{0}".format(reason))

    def nick(self, nickname):
        with self.lock:
            self.send("NICK {0}".format(nickname))

    def user(self, ident, realname):
        self.send("USER {0} {1} {1} :{2}".format(ident, self.address, realname or ident))

    def cap(self, *capabilities):
        self.send("CAP {0}".format(" ".join(capabilities)))

    def kick(self, channel, nick, reason=""):
        with self.lock:
            self.send("KICK {0} {1} :{2}".format(channel, nick, reason))

    def who(self, channel, params):
        with self.lock:
            self.send("WHO {0} :{1}".format(channel, params))

    def ns_identify(self, pw):
        self.msg("NickServ", "IDENTIFY", self.nickname, pw)

    def ns_ghost(self):
        self.msg("NickServ", "GHOST", self.nickname)

    def ns_release(self):
        self.msg("NickServ", "RELEASE", self.nickname)

    def ns_regain(self):
        self.msg("NickServ", "REGAIN", self.nickname)

    def start(self):
        if self.is_fake_connection:
            return

        self.logger("Connecting to {0}:{1}".format(self.address, self.port))

        try:
            retries = 0
            while retries <= 3:
                try:
                    self.socket.connect((self.address, self.port))
                except socket.error as exc:
                    retries += 1
                    self.logger("Error: {0}".format(exc))
                else:
                    break

            if self.server_pass:
                self.send("PASS {0}".format(self.server_pass))

            if self.use_sasl:
                self.cap("LS")

            self.nick(self.nickname)
            self.user(self.ident, self.realname)

            if self.use_sasl:
                self.cap("REQ", "multi-prefix")
                self.cap("REQ", "sasl")

            if self.connect_callback:
                self.connect_callback(self)

            buffer = b""

            while True:
                buffer += self.socket.recv(1024)

                data = buffer.split(b"\n")
                buffer = data.pop()

                for line in data:
                    prefix, command, args = parse_command(line)

                    decoded = [x.decode("utf-8") for x in args]

                    largs = list(args)

                    if prefix is not None:
                        prefix = prefix.decode("utf-8")

                    self.logger("receive <--- {0} {1} ({2})".format(prefix, command, ", ".join(decoded)))

                    if command in Hooks:
                        Hooks[command].caller(self, prefix, *decoded)
                    elif "" in Hooks:
                        Hooks[""].caller(self, prefix, command, *decoded)

        except Exception:
            traceback.print_exc()
            raise

        finally:
            self.logger("Closing socket")
            self.socket.close()

    @property
    def lastsaid(self):
        """Return how many seconds ago was the last sent message."""
        with self.lock:
            return int(time.time() - self._lastsaid)
