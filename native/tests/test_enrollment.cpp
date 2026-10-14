#include "fidologon/enrollment.h"
#include "fidologon/errors.h"
#include "fidologon/fake_authenticator.h"
#include "test_framework.h"

using namespace fidologon;

namespace {

constexpr wchar_t kSid[] = L"S-1-5-21-1-1001";
const std::wstring kPin1234 = L"1234";

FakeAuthenticator& InstallFake() {
    auto fake = std::make_unique<FakeAuthenticator>();
    FakeAuthenticator& ref = *fake;
    ReplaceAuthenticatorForTests(std::move(fake));
    return ref;
}

EnrollRequest Request(const std::wstring& device, bool requirePin, const std::wstring& pin) {
    EnrollRequest request;
    request.devicePath = device;
    request.userSid = kSid;
    request.userName = L"alice";
    request.label = L"test key";
    request.requirePin = requirePin;
    request.pin = pin;
    request.password = L"WindowsPassword!";
    return request;
}

}  // namespace

TEST(EnrollWithPinThenUnlockWithPin) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"1234");
    RecordStore store = RecordStore::OpenDefault();

    const std::wstring id = Enroll(Request(L"dev1", true, L"1234"), store);
    const auto records = store.ListForUser(kSid);
    CHECK_EQ(records.size(), 1u);
    CHECK(records[0].id == id);

    const auto match = FindEnrolledKey(records, &kPin1234);
    CHECK(match.has_value());
    CHECK(match->device.path == L"dev1");
    CHECK(UnlockPassword(*match, L"1234") == L"WindowsPassword!");
    CHECK_THROWS_CODE(UnlockPassword(*match, L""), ErrorCode::PinRequired);
    CHECK_THROWS_CODE(UnlockPassword(*match, L"0000"), ErrorCode::PinInvalid);
}

TEST(TouchOnlyKeyOnDeviceWithPinUnlocksWithoutPin) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"1234");
    RecordStore store = RecordStore::OpenDefault();

    Enroll(Request(L"dev1", false, L"1234"), store);  // PIN only needed to create the credential
    const auto match = FindEnrolledKey(store.ListForUser(kSid));
    CHECK(match.has_value());
    CHECK(UnlockPassword(*match, L"") == L"WindowsPassword!");
}

TEST(TouchOnlyKeyWithoutPinEnrolls) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"dev1", false, L""), store);
    const auto match = FindEnrolledKey(store.ListForUser(kSid));
    CHECK(match.has_value());
    CHECK(UnlockPassword(*match, L"") == L"WindowsPassword!");
}

TEST(EnrollRejectsInvalidCombinations) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"nopin", L"");
    fake.PlugDevice(L"withpin", L"1234");
    RecordStore store = RecordStore::OpenDefault();

    CHECK_THROWS_CODE(Enroll(Request(L"nopin", true, L""), store), ErrorCode::PinNotSet);
    CHECK_THROWS_CODE(Enroll(Request(L"withpin", true, L""), store), ErrorCode::PinRequired);
    CHECK_THROWS_CODE(Enroll(Request(L"withpin", true, L"9999"), store), ErrorCode::PinInvalid);

    EnrollRequest noPassword = Request(L"withpin", true, L"1234");
    noPassword.password.clear();
    CHECK_THROWS_CODE(Enroll(noPassword, store), ErrorCode::InvalidArgument);
    CHECK(store.List().empty());
}

TEST(UnpluggedOrForeignKeyIsNotFound) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"1234");
    fake.PlugDevice(L"dev2", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"dev1", true, L"1234"), store);

    fake.UnplugDevice(L"dev1");
    CHECK(!FindEnrolledKey(store.ListForUser(kSid), &kPin1234).has_value());  // dev2 holds no credential

    fake.PlugDevice(L"dev1", L"1234");
    fake.UnplugDevice(L"dev2");
    CHECK(FindEnrolledKey(store.ListForUser(kSid), &kPin1234).has_value());
    CHECK(!FindEnrolledKey(store.ListForUser(L"S-1-5-21-other"), &kPin1234).has_value());
}

TEST(TwoKeysForOneAccountBothWork) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"main", L"1111");
    fake.PlugDevice(L"backup", L"2222");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"main", true, L"1111"), store);
    Enroll(Request(L"backup", true, L"2222"), store);

    fake.UnplugDevice(L"main");
    const std::wstring pin = L"2222";
    const auto match = FindEnrolledKey(store.ListForUser(kSid), &pin);
    CHECK(match.has_value());
    CHECK(match->device.path == L"backup");
    CHECK(UnlockPassword(*match, L"2222") == L"WindowsPassword!");
}

TEST(CopiedPasswordBlobCannotBeUsedByAnotherRecord) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"dev1", true, L"1234"), store);

    auto match = FindEnrolledKey(store.ListForUser(kSid), &kPin1234);
    CHECK(match.has_value());
    match->record.userSid = L"S-1-5-21-1-1002";  // simulate a record moved to another account
    CHECK_THROWS_CODE(UnlockPassword(*match, L"1234"), ErrorCode::DecryptFailed);
}

TEST(PinModeRequiresAKeyThatEnforcesCredProtect) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"ctap20", L"1234", FakeAuthenticator::CredProtectMode::Unsupported);
    fake.PlugDevice(L"liar", L"1234", FakeAuthenticator::CredProtectMode::AdvertisedOnly);
    RecordStore store = RecordStore::OpenDefault();

    CHECK_THROWS_CODE(Enroll(Request(L"ctap20", true, L"1234"), store), ErrorCode::CredProtectUnsupported);
    CHECK_THROWS_CODE(Enroll(Request(L"liar", true, L"1234"), store), ErrorCode::CredProtectUnsupported);
    CHECK(store.List().empty());

    Enroll(Request(L"ctap20", false, L"1234"), store);  // touch-only stays available
    CHECK_EQ(store.List().size(), 1u);
}

TEST(PinModeCredentialIsUnusableWithoutPinEvenIfRecordIsDowngraded) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"dev1", true, L"1234"), store);
    KeyRecord record = store.ListForUser(kSid).at(0);

    // The key itself hides the credential and refuses hmac-secret without the PIN.
    CHECK(!fake.HasCredential(L"dev1", record.rpId, record.credentialId, nullptr));
    CHECK_THROWS_CODE(fake.GetHmacSecret(L"dev1", record.rpId, record.credentialId, record.hmacSalt, nullptr),
                      ErrorCode::CredentialNotOnDevice);

    // An attacker who flips RequirePin in the registry gains nothing.
    record.requirePin = false;
    store.Save(record);
    CHECK(!FindEnrolledKey(store.ListForUser(kSid), nullptr).has_value());
    CHECK_THROWS_CODE(UnlockPassword(KeyMatch{DeviceInfo{L"dev1", L"", L""}, record}, L""),
                      ErrorCode::CredentialNotOnDevice);
}

TEST(PinIsNeverSentWhenSeveralKeysArePlugged) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"mine", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"mine", true, L"1234"), store);
    const int attemptsAfterEnroll = fake.PinAttempts(L"mine");
    fake.PlugDevice(L"foreign", L"9999");

    CHECK_THROWS_CODE(FindEnrolledKey(store.ListForUser(kSid), &kPin1234), ErrorCode::MultipleDevices);
    CHECK_EQ(fake.PinAttempts(L"foreign"), 0);
    CHECK_EQ(fake.PinAttempts(L"mine"), attemptsAfterEnroll);

    fake.UnplugDevice(L"foreign");
    CHECK(FindEnrolledKey(store.ListForUser(kSid), &kPin1234).has_value());
}

TEST(MissingPinIsReportedBeforeAnyPinAttempt) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"dev1", true, L"1234"), store);
    const int attempts = fake.PinAttempts(L"dev1");
    const std::wstring empty;

    CHECK_THROWS_CODE(FindEnrolledKey(store.ListForUser(kSid), &empty), ErrorCode::PinRequired);
    CHECK_THROWS_CODE(FindEnrolledKey(store.ListForUser(kSid), nullptr), ErrorCode::PinRequired);
    CHECK_EQ(fake.PinAttempts(L"dev1"), attempts);

    fake.UnplugDevice(L"dev1");
    CHECK(!FindEnrolledKey(store.ListForUser(kSid), &empty).has_value());  // no key: NoDevice, not PinRequired
}

TEST(TouchOnlyKeyIsFoundSilentlyAmongSeveralKeys) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"touch", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"touch", false, L"1234"), store);
    fake.PlugDevice(L"other", L"5555");
    const int attempts = fake.PinAttempts(L"touch");

    const auto match = FindEnrolledKey(store.ListForUser(kSid), nullptr);
    CHECK(match.has_value());
    CHECK(match->device.path == L"touch");
    CHECK_EQ(fake.PinAttempts(L"touch"), attempts);
    CHECK_EQ(fake.PinAttempts(L"other"), 0);
}

TEST(EnrollmentRecordsUsbIdsAndOtherModelsAreNeverOpened) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"mine", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"mine", true, L"1234"), store);
    const KeyRecord record = store.ListForUser(kSid).at(0);
    CHECK_EQ(record.vendorId, FakeAuthenticator::kVendorId);
    CHECK_EQ(record.productId, FakeAuthenticator::kProductId);

    // A device of another model plugged at the sign-in screen is not touched, and does not
    // count as a second candidate key either.
    fake.PlugDevice(L"hostile", L"", FakeAuthenticator::CredProtectMode::Enforced, 0x1234, 0x5678);
    CHECK(FindEnrolledKey(store.ListForUser(kSid), &kPin1234).has_value());
    CHECK_EQ(fake.Exchanges(L"hostile"), 0);

    fake.UnplugDevice(L"mine");
    CHECK(!FindEnrolledKey(store.ListForUser(kSid), &kPin1234).has_value());
    CHECK_EQ(fake.Exchanges(L"hostile"), 0);
}

TEST(MissingPinIsReportedWithoutOpeningTheKey) {
    FakeAuthenticator& fake = InstallFake();
    fake.PlugDevice(L"dev1", L"1234");
    RecordStore store = RecordStore::OpenDefault();
    Enroll(Request(L"dev1", true, L"1234"), store);
    const int exchanges = fake.Exchanges(L"dev1");
    const std::wstring empty;
    CHECK_THROWS_CODE(FindEnrolledKey(store.ListForUser(kSid), &empty), ErrorCode::PinRequired);
    CHECK_EQ(fake.Exchanges(L"dev1"), exchanges);
}

TEST(EveryEnabledUserEnrolledIgnoresDisabledAccounts) {
    KeyRecord record;
    record.userSid = L"S-1";
    const std::vector<KeyRecord> records{record};

    CHECK(EveryEnabledUserEnrolled({{L"alice", L"", L"S-1", false}, {L"Guest", L"", L"S-2", true}}, records));
    CHECK(!EveryEnabledUserEnrolled({{L"alice", L"", L"S-1", false}, {L"bob", L"", L"S-3", false}}, records));
    CHECK(!EveryEnabledUserEnrolled({{L"Guest", L"", L"S-2", true}}, records));
    CHECK(!EveryEnabledUserEnrolled({}, records));
}
