// Scripted opendnp3 2.1.0-RC5 SAv5 master used to exercise the Bayline outstation.
#include <asiodnp3/DNP3Manager.h>
#include <asiodnp3/ConsoleLogger.h>
#include <asiodnp3/DefaultMasterApplication.h>
#include <asiopal/UTCTimeSource.h>
#include <opendnp3/LogLevels.h>
#include <opendnp3/app/ControlRelayOutputBlock.h>
#include <opendnp3/app/AnalogOutput.h>
#include <osslcrypto/CryptoProvider.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <future>
#include <map>
#include <set>
#include <iostream>
#include <thread>

using namespace std;
using namespace openpal;
using namespace asiopal;
using namespace asiodnp3;
using namespace opendnp3;
using namespace secauth;

static vector<uint8_t> hex(const string& s) { vector<uint8_t> v; for (size_t i = 0; i + 1 < s.size(); i += 2) v.push_back((uint8_t)stoi(s.substr(i, 2), nullptr, 16)); return v; }
static RSlice sl(const vector<uint8_t>& v) { return RSlice(v.data(), (uint32_t)v.size()); }
static int failures = 0;
static void verdict(bool ok, const string& what) { cout << (ok ? "PASS " : "FAIL ") << what << endl; if (!ok) ++failures; }

class App final : public IMasterApplicationSA
{
public:
	virtual UTCTimestamp Now() override { return UTCTimeSource::Instance().Now(); }
	virtual void OnTaskComplete(const TaskInfo& info) override { cout << "task " << MasterTaskTypeToString(info.type) << " -> " << TaskCompletionToString(info.result) << endl; }
	virtual void PersistNewUpdateKey(const std::string& username, opendnp3::User user, const UpdateKey& key) override { cout << "master persisted new update key for " << username << " user " << user.GetId() << endl; }
};

// Records what the master decodes instead of printing it, so the checks can look at the data.
class Recorder final : public ISOEHandler
{
public:
	mutex lock;
	map<string, set<uint16_t>> seen;
	map<uint16_t, double> analogs;
	template <class T> void Note(const string& kind, const ICollection<Indexed<T>>& values)
	{
		lock_guard<mutex> guard(lock);
		values.ForeachItem([&](const Indexed<T>& item) { seen[kind].insert(item.index); });
	}
	size_t Count(const string& kind) { lock_guard<mutex> guard(lock); return seen[kind].size(); }
	double AnalogValue(uint16_t index) { lock_guard<mutex> guard(lock); return analogs.count(index) ? analogs[index] : -9999; }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<Binary>>& v) override { Note("binary", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<DoubleBitBinary>>& v) override { Note("double", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<Analog>>& v) override
	{
		Note("analog", v);
		lock_guard<mutex> guard(lock);
		v.ForeachItem([&](const Indexed<Analog>& item) { analogs[item.index] = item.value.value; });
	}
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<Counter>>& v) override { Note("counter", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<FrozenCounter>>& v) override { Note("frozen", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<BinaryOutputStatus>>& v) override { Note("bostatus", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<AnalogOutputStatus>>& v) override { Note("aostatus", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<OctetString>>& v) override { Note("octet", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<TimeAndInterval>>& v) override { Note("tai", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<BinaryCommandEvent>>& v) override { Note("bcmd", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<AnalogCommandEvent>>& v) override { Note("acmd", v); }
	virtual void Process(const HeaderInfo&, const ICollection<Indexed<SecurityStat>>& v) override { Note("secstat", v); }
protected:
	virtual void Start() override {}
	virtual void End() override {}
};

static void CheckIntegrity(Recorder& data)
{
	verdict(data.Count("binary") == 20 && data.Count("bostatus") == 9 && data.Count("counter") == 7 && data.Count("analog") == 20 && data.Count("aostatus") == 2,
	        "integrity poll delivered 20 BI, 9 BO, 7 counters, 20 AI, 2 AO");
	verdict(data.Count("secstat") == 18, "integrity poll delivered all 18 g121 security statistics");
}

struct Result { TaskCompletion summary = TaskCompletion::FAILURE_NO_COMMS; CommandStatus status = CommandStatus::UNDEFINED; };

static Result Wait(function<void(CommandCallbackT)> start)
{
	auto p = make_shared<promise<Result>>();
	start([p](const ICommandTaskResult& r) {
		Result out; out.summary = r.summary;
		r.ForeachItem([&](const CommandPointResult& item) { out.status = item.status; });
		p->set_value(out);
	});
	auto f = p->get_future();
	if (f.wait_for(chrono::seconds(10)) != future_status::ready) return Result();
	return f.get();
}

static Result Crob(ICommandProcessor* m, ControlCode code, uint16_t index, User user, bool sbo)
{
	return Wait([&](CommandCallbackT cb) {
		CommandSet set; set.StartHeader<ControlRelayOutputBlock>().Add(ControlRelayOutputBlock(code), index);
		if (sbo) m->SelectAndOperate(move(set), cb, TaskConfig::With(user)); else m->DirectOperate(move(set), cb, TaskConfig::With(user));
	});
}

int main(int argc, char* argv[])
{
	if (argc < 3) { cerr << "usage: satest <port> <user1-key-hex> [user2-key-hex|-] [authority-key-hex] [outstation-name]" << endl; return 2; }
	uint16_t port = (uint16_t)stoi(argv[1]);
	auto key1 = string(argv[2]) == "plain" ? vector<uint8_t>() : hex(argv[2]);
	string key2hex = argc > 3 ? argv[3] : "-";
	string authhex = argc > 4 ? argv[4] : "";
	string osname = argc > 5 ? argv[5] : "Riverside 12 kV";

	if (string(argv[2]) == "plain")
	{
		DNP3Manager manager(1);
		manager.AddLogSubscriber(ConsoleLogger::Instance());
		auto channel = manager.AddTCPClient("tcp", levels::NORMAL, ChannelRetry::Default(), "127.0.0.1", "0.0.0.0", port);
		MasterStackConfig config;
		config.master.responseTimeout = TimeDuration::Seconds(3);
		config.link.LocalAddr = 100;
		config.link.RemoteAddr = 4;
		Recorder data;
		auto master = channel->AddMaster("master", data, DefaultMasterApplication::Instance(), config);
		master->Enable();
		this_thread::sleep_for(chrono::seconds(3));
		CheckIntegrity(data);
		double tap = data.AnalogValue(12);
		auto inhibit = Crob(master, ControlCode::PULSE_ON, 5, User::Default(), false);
		verdict(inhibit.status == CommandStatus::AUTOMATION_INHIBIT, "tap raise while the 90 is in auto returns AUTOMATION_INHIBIT");
		auto manual = Crob(master, ControlCode::LATCH_OFF, 7, User::Default(), true);
		verdict(manual.summary == TaskCompletion::SUCCESS && manual.status == CommandStatus::SUCCESS, "select/operate 90 auto/manual to manual");
		auto raise = Crob(master, ControlCode::PULSE_ON, 5, User::Default(), true);
		verdict(raise.summary == TaskCompletion::SUCCESS && raise.status == CommandStatus::SUCCESS, "select/operate tap raise");
		auto cap = Crob(master, ControlCode::LATCH_ON, 4, User::Default(), false);
		verdict(cap.summary == TaskCompletion::SUCCESS && cap.status == CommandStatus::SUCCESS, "direct operate capacitor bank close");
		auto bad = Crob(master, ControlCode::LATCH_ON, 40, User::Default(), false);
		verdict(bad.status == CommandStatus::NOT_SUPPORTED, "control on a missing output returns NOT_SUPPORTED");
		master->ScanClasses(ClassField::AllClasses());
		this_thread::sleep_for(chrono::seconds(2));
		verdict(data.AnalogValue(12) == tap + 1, "tap position AI 12 rose by one step after the raise");
		cout << (failures ? "PLAINTEST FAILED " : "PLAINTEST OK ") << failures << endl;
		manager.Shutdown();
		return failures ? 1 : 0;
	}

	App app;
	osslcrypto::CryptoProvider crypto;
	DNP3Manager manager(1, &crypto);
	manager.AddLogSubscriber(ConsoleLogger::Instance());
	auto channel = manager.AddTCPClient("tcp", levels::NORMAL, ChannelRetry::Default(), "127.0.0.1", "0.0.0.0", port);
	secauth::MasterAuthStackConfig config;
	config.master.responseTimeout = TimeDuration::Seconds(3);
	config.master.disableUnsolOnStartup = true;
	config.link.LocalAddr = 100;
	config.link.RemoteAddr = 4;
	Recorder data;
	auto master = channel->AddMasterSA("master", data, app, config);
	master->AddUser(User::Default(), UpdateKey(sl(key1)));
	if (key2hex != "-") master->AddUser(User(2), UpdateKey(sl(hex(key2hex))));
	master->Enable();
	this_thread::sleep_for(chrono::seconds(4));
	CheckIntegrity(data);

	auto open = Crob(master, ControlCode::LATCH_OFF, 1, User::Default(), true);
	verdict(open.summary == TaskCompletion::SUCCESS && open.status == CommandStatus::SUCCESS, "user 1 select/operate LATCH_OFF on BO 1 (challenge + reply)");
	auto close = Crob(master, ControlCode::LATCH_ON, 1, User::Default(), false);
	verdict(close.summary == TaskCompletion::SUCCESS && close.status == CommandStatus::SUCCESS, "user 1 direct operate LATCH_ON on BO 1");
	auto ao = Wait([&](CommandCallbackT cb) {
		CommandSet set; set.StartHeader<AnalogOutputFloat32>().Add(AnalogOutputFloat32(12.6f), 0);
		master->DirectOperate(move(set), cb, TaskConfig::With(User::Default()));
	});
	verdict(ao.summary == TaskCompletion::SUCCESS && ao.status == CommandStatus::SUCCESS, "user 1 direct operate g41v3 12.6 kV on AO 0");

	if (key2hex != "-")
	{
		auto viewer = Crob(master, ControlCode::LATCH_OFF, 2, User(2), false);
		verdict(viewer.summary != TaskCompletion::SUCCESS, "user 2 (Viewer) direct operate is refused");
	}

	if (!authhex.empty())
	{
		auto auth = hex(authhex);
		const string name = "bob";
		uint32_t scs = argc > 6 ? (uint32_t)stoul(argv[6]) : 0;
		uint16_t role = 1, days = 30;
		uint8_t fields[11] = { 1, (uint8_t)scs, (uint8_t)(scs >> 8), (uint8_t)(scs >> 16), (uint8_t)(scs >> 24), (uint8_t)role, (uint8_t)(role >> 8), (uint8_t)days, (uint8_t)(days >> 8), (uint8_t)name.size(), 0 };
		vector<uint8_t> msg(fields, fields + 11); msg.insert(msg.end(), name.begin(), name.end());
		vector<uint8_t> cert(32); unsigned int len = 32;
		HMAC(EVP_sha256(), auth.data(), (int)auth.size(), msg.data(), msg.size(), cert.data(), &len);
		master->ChangeUserStatus(UserStatusChange(KeyChangeMethod::AES_256_SHA256_HMAC, UserOperation::OP_ADD, scs, role, days, name, RSlice::Empty(), sl(cert)));
		this_thread::sleep_for(chrono::seconds(2));

		auto p = make_shared<promise<BeginUpdateKeyChangeResult>>();
		master->BeginUpdateKeyChange(name, TaskConfig::Default(), [p](const BeginUpdateKeyChangeResult& r) { p->set_value(r); });
		auto f = p->get_future();
		bool begun = f.wait_for(chrono::seconds(10)) == future_status::ready;
		BeginUpdateKeyChangeResult begin = begun ? f.get() : BeginUpdateKeyChangeResult(TaskCompletion::FAILURE_NO_COMMS);
		verdict(begin.result == TaskCompletion::SUCCESS, "g120v11 update key change request answered with g120v12");
		if (begin.result == TaskCompletion::SUCCESS)
		{
			vector<uint8_t> newkey(32); RAND_bytes(newkey.data(), 32);
			vector<uint8_t> plain(name.begin(), name.end());
			plain.insert(plain.end(), newkey.begin(), newkey.end());
			auto och = begin.outstationChallengeData.ToRSlice();
			plain.insert(plain.end(), (const uint8_t*)och, (const uint8_t*)och + och.Size());
			while (plain.size() % 8) plain.push_back(0);
			AES_KEY k; AES_set_encrypt_key(auth.data(), (int)auth.size() * 8, &k);
			vector<uint8_t> wrapped(plain.size() + 8);
			int wl = AES_wrap_key(&k, nullptr, wrapped.data(), plain.data(), (unsigned)plain.size());
			wrapped.resize(wl > 0 ? wl : 0);
			master->FinishUpdateKeyChange(FinishUpdateKeyChangeArgs(name, osname, begin.user, begin.keyChangeSequenceNum,
				begin.masterChallengeData.ToRSlice(), och, sl(wrapped), UpdateKey(sl(newkey))), TaskConfig::Default());
			this_thread::sleep_for(chrono::seconds(4));
			auto bob = Crob(master, ControlCode::LATCH_OFF, 2, begin.user, true);
			verdict(bob.summary == TaskCompletion::SUCCESS && bob.status == CommandStatus::SUCCESS, "new user bob (Operator) select/operate after the remote update key change");
			auto back = Crob(master, ControlCode::LATCH_ON, 2, begin.user, false);
			verdict(back.summary == TaskCompletion::SUCCESS && back.status == CommandStatus::SUCCESS, "bob direct operate LATCH_ON on BO 2");
		}
	}
	cout << (failures ? "SATEST FAILED " : "SATEST OK ") << failures << endl;
	manager.Shutdown();
	return failures ? 1 : 0;
}
