#include "fidologon/errors.h"
#include "fidologon/record_store.h"
#include "test_framework.h"

using namespace fidologon;

namespace {

KeyRecord SampleRecord(const std::wstring& sid) {
    KeyRecord record;
    record.id = NewRecordId();
    record.userSid = sid;
    record.userName = L"alice";
    record.label = L"Blue key";
    record.credentialId = Bytes{1, 2, 3, 4};
    record.hmacSalt = Bytes(32, 7);
    record.encryptedPassword = Bytes{9, 9, 9};
    record.requirePin = false;
    record.createdUnix = 1700000000;
    return record;
}

}  // namespace

TEST(StoreStartsEmptyWithFallbackAllowed) {
    RecordStore store = RecordStore::OpenDefault();
    CHECK(store.List().empty());
    CHECK(store.AllowPasswordFallback());
    CHECK(store.LockOnKeyRemoval());
    CHECK(store.ShouldLockOnRemoval(L""));
    CHECK(!store.TakeLastAuth().has_value());
}

TEST(StoreSavesListsAndRemovesRecords) {
    RecordStore store = RecordStore::OpenDefault();
    const KeyRecord first = SampleRecord(L"S-1-5-21-1-1001");
    const KeyRecord second = SampleRecord(L"S-1-5-21-1-1002");
    store.Save(first);
    store.Save(second);

    CHECK_EQ(store.List().size(), 2u);
    const auto forUser = store.ListForUser(L"s-1-5-21-1-1001");  // SID comparison is case-insensitive
    CHECK_EQ(forUser.size(), 1u);

    const auto loaded = store.Get(first.id);
    CHECK(loaded.has_value());
    CHECK(loaded->userName == first.userName);
    CHECK(loaded->label == first.label);
    CHECK(loaded->rpId == std::wstring(kDefaultRpId));
    CHECK(loaded->credentialId == first.credentialId);
    CHECK(loaded->hmacSalt == first.hmacSalt);
    CHECK(loaded->encryptedPassword == first.encryptedPassword);
    CHECK_EQ(loaded->requirePin, false);
    CHECK_EQ(loaded->createdUnix, first.createdUnix);
    CHECK(!loaded->lockOnRemoval.has_value());

    CHECK(store.Remove(first.id));
    CHECK(!store.Remove(first.id));
    CHECK_EQ(store.List().size(), 1u);
}

TEST(StoreRejectsIncompleteRecordsAndBadIds) {
    RecordStore store = RecordStore::OpenDefault();
    KeyRecord record = SampleRecord(L"S-1-5-21-1-1001");
    record.encryptedPassword.clear();
    CHECK_THROWS_CODE(store.Save(record), ErrorCode::InvalidArgument);
    CHECK_THROWS_CODE(store.Remove(L"..\\Keys"), ErrorCode::InvalidArgument);
}

TEST(StorePersistsPasswordFallbackOption) {
    RecordStore store = RecordStore::OpenDefault();
    store.SetAllowPasswordFallback(false);
    CHECK(!RecordStore::OpenDefault().AllowPasswordFallback());
    store.SetAllowPasswordFallback(true);
    CHECK(RecordStore::OpenDefault().AllowPasswordFallback());
}

TEST(LockOnRemovalFollowsMachineOptionUnlessOverridden) {
    RecordStore store = RecordStore::OpenDefault();
    const KeyRecord record = SampleRecord(L"S-1-5-21-1-1001");
    store.Save(record);

    CHECK(store.ShouldLockOnRemoval(record.id));
    store.SetLockOnKeyRemoval(false);
    CHECK(!RecordStore::OpenDefault().LockOnKeyRemoval());
    CHECK(!store.ShouldLockOnRemoval(record.id));
    CHECK(!store.ShouldLockOnRemoval(L"{unknown}"));

    store.SetRecordLockOnRemoval(record.id, true);
    CHECK(store.Get(record.id)->lockOnRemoval == std::optional<bool>(true));
    CHECK(store.ShouldLockOnRemoval(record.id));

    store.SetLockOnKeyRemoval(true);
    store.SetRecordLockOnRemoval(record.id, false);
    CHECK(!store.ShouldLockOnRemoval(record.id));
    CHECK(store.ShouldLockOnRemoval(L"{unknown}"));

    store.SetRecordLockOnRemoval(record.id, std::nullopt);
    CHECK(!store.Get(record.id)->lockOnRemoval.has_value());
    CHECK(store.ShouldLockOnRemoval(record.id));
    store.SetRecordLockOnRemoval(record.id, std::nullopt);  // removing a missing override is fine

    CHECK_THROWS_CODE(store.SetRecordLockOnRemoval(L"{unknown}", true), ErrorCode::NotFound);
    CHECK_THROWS_CODE(store.SetRecordLockOnRemoval(L"..\\Keys", true), ErrorCode::InvalidArgument);
}

TEST(LastAuthIsTakenOnlyByItsSession) {
    RecordStore store = RecordStore::OpenDefault();
    store.WriteLastAuth(LastAuth{L"S-1-5-21-1-1001", L"dev", L"{rec}", 42, 3, 0x1234567890ULL});

    std::optional<LastAuth> other;
    CHECK(!store.TakeLastAuthForSession(1, &other).has_value());
    CHECK(other.has_value());
    CHECK_EQ(other->sessionId, 3u);

    const auto taken = store.TakeLastAuthForSession(3);
    CHECK(taken.has_value());
    CHECK(taken->recordId == L"{rec}");
    CHECK_EQ(taken->deviceArrival, 0x1234567890ULL);
    CHECK(!store.TakeLastAuthForSession(3).has_value());
}

TEST(SessionBindingsSurviveLastAuthCleanup) {
    RecordStore store = RecordStore::OpenDefault();
    store.SaveSessionBinding(SessionBinding{1, L"S-1", L"dev1", L"{a}"});
    store.SaveSessionBinding(SessionBinding{7, L"S-2", L"dev2", L"{b}", 99});
    store.WriteLastAuth(LastAuth{L"S", L"P", L"R", 1});
    store.ClearLastAuth();
    CHECK(!store.TakeLastAuth().has_value());

    auto bindings = store.ListSessionBindings();
    CHECK_EQ(bindings.size(), 2u);
    store.RemoveSessionBinding(1);
    store.RemoveSessionBinding(42);  // unknown session: no error
    bindings = store.ListSessionBindings();
    CHECK_EQ(bindings.size(), 1u);
    CHECK_EQ(bindings[0].sessionId, 7u);
    CHECK(bindings[0].devicePath == L"dev2");
    CHECK(bindings[0].recordId == L"{b}");
    CHECK_EQ(bindings[0].deviceArrival, 99ULL);
}

TEST(LastAuthIsTakenOnlyOnce) {
    RecordStore store = RecordStore::OpenDefault();
    store.WriteLastAuth(LastAuth{L"S-1-5-21-1-1001", L"\\\\?\\hid#vid_1050", L"{rec}", 42});
    const auto taken = store.TakeLastAuth();
    CHECK(taken.has_value());
    CHECK(taken->devicePath == L"\\\\?\\hid#vid_1050");
    CHECK(taken->recordId == L"{rec}");
    CHECK_EQ(taken->timestampFileTime, 42u);
    CHECK(!store.TakeLastAuth().has_value());

    store.WriteLastAuth(LastAuth{L"S", L"P", L"R", 1});
    store.ClearLastAuth();
    CHECK(!store.TakeLastAuth().has_value());
}
