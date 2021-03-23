from dllcharacteristics import *
import pytest
import pefile

def test_main():
    assert get_characteristic_by_value(0x0080) == 'FORCE_INTEGRITY'
    assert get_characteristic_by_value(0x8000) == 'TERMINAL_SERVER_AWARE'

    with pytest.raises(Exception):
        get_characteristic_by_value(0x9999)

    assert get_flag_value_by_name('force_integrity')
    assert get_flag_value_by_name('WDM_DRIVER')
    with pytest.raises(Exception):
        get_flag_value_by_name('TEST_ERROR')
    

    pe = pefile.PE('test.exe')
    assert get_characteristic(pe, get_flag_value_by_name('dynamic_base')) == 1
    assert get_characteristic(pe, get_flag_value_by_name('FORCE_INTEGRITY')) == 0

    with pytest.raises(Exception):
        get_characteristic(pe, get_flag_value_by_name('TEST')) == 'OFF'

    set_characteristic(pe, get_flag_value_by_name('dynamic_base'), 0)
    assert get_characteristic(pe, get_flag_value_by_name('dynamic_base')) == 0

    set_characteristic(pe, get_flag_value_by_name('FORCE_INTEGRITY'), 1)
    assert get_characteristic(pe, get_flag_value_by_name('FORCE_INTEGRITY')) == 1

    with pytest.raises(SystemExit):
        set_characteristic(pe, get_flag_value_by_name('dynamic_base'), 99)
