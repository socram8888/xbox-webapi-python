def test_people_friends_own(vcr_session, xbl_client):
    with vcr_session.use_cassette('people_friends_own.json'):
        ret = xbl_client.people.get_friends_own()

        assert ret.status_code == 200
        data = ret.json()

        assert data['totalCount'] == 2
        assert len(data['people']) == 2


def test_people_summary_by_gamertag(vcr_session, xbl_client):
    with vcr_session.use_cassette('people_summary_by_gamertag.json'):
        ret = xbl_client.people.get_friends_summary_by_gamertag('e')

        assert ret.status_code == 200
        data = ret.json()

        assert data['targetFollowingCount'] == 0
        assert data['targetFollowerCount'] == 20991
        assert data['isCallerFollowingTarget'] is False
        assert data['isTargetFollowingCaller'] is False
        assert data['hasCallerMarkedTargetAsFavorite'] is False
        assert data['hasCallerMarkedTargetAsKnown'] is False
        assert data['legacyFriendStatus'] == 'None'


def test_people_summary_by_xuid(vcr_session, xbl_client):
    with vcr_session.use_cassette('people_summary_by_xuid.json'):
        ret = xbl_client.people.get_friends_summary_by_xuid('2669321029139235')
        assert ret.status_code == 200
        data = ret.json()

        assert data['targetFollowingCount'] == 0
        assert data['targetFollowerCount'] == 20991
        assert data['isCallerFollowingTarget'] is False
        assert data['isTargetFollowingCaller'] is False
        assert data['hasCallerMarkedTargetAsFavorite'] is False
        assert data['hasCallerMarkedTargetAsKnown'] is False
        assert data['legacyFriendStatus'] == 'None'


def test_people_summary_own(vcr_session, xbl_client):
    with vcr_session.use_cassette('people_summary_own.json'):
        ret = xbl_client.people.get_friends_summary_own()

        assert ret.status_code == 200
        data = ret.json()

        assert data['targetFollowingCount'] == 2
        assert data['targetFollowerCount'] == 1
        assert data['isCallerFollowingTarget'] is False
        assert data['isTargetFollowingCaller'] is False
        assert data['hasCallerMarkedTargetAsFavorite'] is False
        assert data['hasCallerMarkedTargetAsKnown'] is False
        assert data['legacyFriendStatus'] == 'None'
        assert data['availablePeopleSlots'] == 998
        assert data['recentChangeCount'] == 1
        assert data['watermark'] == '5248264408914225648'


def test_profiles_batch(vcr_session, xbl_client):
    with vcr_session.use_cassette('people_batch.json'):
        ret = xbl_client.people.get_friends_own_batch(
            ['2669321029139235', '2584878536129841']
        )

        assert ret.status_code == 200
        data = ret.json()

        assert data['totalCount'] == 2
        assert len(data['people']) == 2
