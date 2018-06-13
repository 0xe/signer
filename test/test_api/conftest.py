import pytest
import uuid

'''
Adding the command line parameter to get the environment against which the tests need to be run with the right config.
'''

def pytest_addoption(parser):
    parser.addoption("--env", action="store",dest="envvar",default="rqa3", help="Environment can be : rqa3,prod,rqa2....")


def pytest_runtest_setup(item):
    envmarker = item.get_marker("env")
    if envmarker is not None:
        envname = envmarker.args[0]
        if not item.config.getoption("--env") in envname:
            pytest.skip()
        #return item.config.getoption("--env")

@pytest.fixture
def config(request):
    env=request.config.option.envvar
    config = {}
    config_file="configs/"+env+".cfg"
    print config_file
    for i in map(lambda x: x.split('='), open(config_file).read().strip().split('\n')):
        config[i[0]] = i[1]
    config['env'] = env
    testuuid = str(uuid.uuid4())
    headers = {}
    config['headers'] = headers
    return config
