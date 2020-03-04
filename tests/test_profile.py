def test_profile_by_xuid(vcr_session, xbl_client):
    with vcr_session.use_cassette('profile_by_xuid.json'):
        ret = xbl_client.profile.get_profile_by_xuid('2669321029139235')

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['profileUsers']) == 1
        assert data['profileUsers'][0]['id'] == '2669321029139235'


def test_profile_by_gamertag(vcr_session, xbl_client):
    with vcr_session.use_cassette('profile_by_gamertag.json'):
        ret = xbl_client.profile.get_profile_by_gamertag('e')

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['profileUsers']) == 1
        assert data['profileUsers'][0]['id'] == '2669321029139235'


def test_profiles_batch(vcr_session, xbl_client):
    with vcr_session.use_cassette('profile_batch.json'):
        ret = xbl_client.profile.get_profiles(['2669321029139235', '2584878536129841'])

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['profileUsers']) == 2
