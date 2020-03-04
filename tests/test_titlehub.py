def test_titlehub_titlehistory(vcr_session, xbl_client):
    with vcr_session.use_cassette('titlehub_titlehistory.json'):
        ret = xbl_client.titlehub.get_title_history(987654321)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['titles']) == 5


def test_titlehub_titleinfo(vcr_session, xbl_client):
    with vcr_session.use_cassette('titlehub_titleinfo.json'):
        ret = xbl_client.titlehub.get_title_info(1717113201)

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['titles']) == 1


def test_titlehub_batch(vcr_session, xbl_client):
    with vcr_session.use_cassette('titlehub_batch.json'):
        ret = xbl_client.titlehub.get_titles_batch(
            ['Microsoft.SeaofThieves_8wekyb3d8bbwe', 'Microsoft.XboxApp_8wekyb3d8bbwe']
        )

        assert ret.status_code == 200
        data = ret.json()

        assert len(data['titles']) == 2
