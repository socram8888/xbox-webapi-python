def test_profile_by_xuid(vcr_session, xbl_client):
    with vcr_session.use_cassette('usersearch_live_search.json'):
        ret = xbl_client.usersearch.get_live_search('tux')

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['results']) == 8
        result = data['results'][0]

        assert result['text'] == 'Tux'
        assert result['result']['id'] == '2533274895244106'
        assert result['result']['score'] == 0.0
        assert result['result']['gamertag'] == 'Tux'
        assert result['result']['displayPicUri'].startswith('http://images-eds.xboxlive.com/image?url=')
