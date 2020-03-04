def test_gameclips_recent_xuid(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_recent_xuid.json'):
        ret = xbl_client.gameclips.get_recent_clips_by_xuid('2669321029139235', skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_recent_xuid_titleid_filter(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_recent_xuid_titleid.json'):
        ret = xbl_client.gameclips.get_recent_clips_by_xuid('2669321029139235', title_id=219630713, skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_recent_own(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_recent_own.json'):
        ret = xbl_client.gameclips.get_recent_own_clips(skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_recent_own_titleid_filter(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_recent_own_titleid.json'):
        ret = xbl_client.gameclips.get_recent_own_clips(title_id=219630713, skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_recent_community(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_recent_community.json'):
        ret = xbl_client.gameclips.get_recent_community_clips_by_title_id('219630713')

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 99


def test_gameclips_saved_xuid(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_saved_xuid.json'):
        ret = xbl_client.gameclips.get_saved_clips_by_xuid('2669321029139235', skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_saved_xuid_titleid_filter(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_saved_xuid_titleid.json'):
        ret = xbl_client.gameclips.get_saved_clips_by_xuid('2669321029139235', title_id=219630713, skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_saved_own(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_saved_own.json'):
        ret = xbl_client.gameclips.get_saved_own_clips(skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_saved_own_titleid_filter(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_saved_own_titleid.json'):
        ret = xbl_client.gameclips.get_saved_own_clips(title_id=219630713, skip_items=0, max_items=25)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 25


def test_gameclips_saved_community(vcr_session, xbl_client):
    with vcr_session.use_cassette('gameclips_saved_community.json'):
        ret = xbl_client.gameclips.get_saved_community_clips_by_title_id(219630713)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['gameClips']) == 99
