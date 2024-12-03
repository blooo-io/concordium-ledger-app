import pytest

from application_client.boilerplate_transaction import Transaction
from application_client.boilerplate_command_sender import (
    BoilerplateCommandSender,
    Errors,
    InsType,
)
from application_client.boilerplate_response_unpacker import (
    unpack_get_public_key_response,
    unpack_sign_tx_response,
)
from ragger.error import ExceptionRAPDU
from ragger.navigator import NavInsID
from utils import check_signature_validity

# In this tests we check the behavior of the device when asked to sign a transaction


# In this test we send to the device a transaction to sign and validate it on screen
# The transaction is short and will be sent in one chunk
# We will ensure that the displayed information is correct by using screenshots comparison
def test_sign_tx_simple_transfer(backend, scenario_navigator):
    # Use the app interface instead of raw interface
    client = BoilerplateCommandSender(backend)
    # The path used for this entire test
    path: str = "m/1105/0/0/0/0/2/0/0"

    # First we need to get the public key of the device in order to build the transaction
    # rapdu = client.get_public_key(path=path)
    # _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

    # Create the transaction that will be sent to the device for signing
    transaction = "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da70320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7ffffffffffffffff"
    transaction = bytes.fromhex(transaction)

    # Send the sign device instruction.
    # As it requires on-screen validation, the function is asynchronous.
    # It will yield the result when the navigation is done
    ins_type = InsType.SIGN_SIMPLE_TRANSFER
    with client.sign_tx(path=path, tx_type_ins=ins_type, transaction=transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        scenario_navigator.review_approve()

    # The device as yielded the result, parse it and ensure that the signature is correct
    response = client.get_async_response().data
    response_hex = response.hex()
    print("response", response_hex)
    assert (
        response_hex
        == "d1617ee706805c0bc6a43260ece93a7ceba37aaefa303251cf19bdcbbe88c0a3d3878dcb965cdb88ff380fdb1aa4b321671f365d7258e878d18fa1b398a1a10f"
    )
    # assert check_signature_validity(public_key, der_sig, transaction)


def test_sign_tx_with_schedule(backend, scenario_navigator):
    client = BoilerplateCommandSender(backend)
    path: str = "m/1105/0/0/0/0/2/0/0"
    ins_type = InsType.SIGN_TRANSFER_WITH_SCHEDULE
    transaction = bytes.fromhex(
        "20a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7000000000000000a0000000000000064000000290000000063de5da71320a845815bd43a1999e90fbf971537a70392eb38f89e6bd32b3dd70e1a9551d7050000017a396883d90000000005f5e1000000017a396883d90000000005f5e1000000017a396883d90000000005f5e1000000017a396883d90000000005f5e1000000017a396883d90000000005f5e100"
    )
    with client.sign_tx(path=path, tx_type_ins=ins_type, transaction=transaction):
        # Validate the on-screen request by performing the navigation appropriate for this device
        scenario_navigator.review_approve()
    response = client.get_async_response().data
    response_hex = response.hex()
    print("response", response_hex)
    assert (
        response_hex
        == "e22fa38f78a79db71e84376c4eec2382166cdc412994207e7631b0ba3828f069b17b6f30351a64c50e5efacec3fe25161e9f7131e0235cd740739b24e0b06308"
    )


# def test_sign_tx_with_schedule_41_pairs(backend, scenario_navigator):
#     client = BoilerplateCommandSender(backend)
#     path: str = "m/1105/0/0/0/0/2/0/0"
#     ins_type = InsType.SIGN_TRANSFER_WITH_SCHEDULE
#     transaction = bytes.fromhex(
#         "b9e2f8c1f204b9b51672c5d72729f61cb79254d7cd5fc535dbe6e625b3ec0e9500000000000004d200000000000004d2000002b2000000000001e24013b9e2f8c1f204b9b51672c5d72729f61cb79254d7cd5fc535dbe6e625b3ec0e9529000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7000000000001e24000000000000003e7"
#     )
#     with client.sign_tx(path=path, tx_type_ins=ins_type, transaction=transaction):
#         # Validate the on-screen request by performing the navigation appropriate for this device
#         scenario_navigator.review_approve()
#     response = client.get_async_response().data
#     response_hex = response.hex()
#     print("response", response_hex)
#     # TODO: enter correct signature
#     assert (
#         response_hex
#         == "5946a5ba05012ddb5ffe4f50a56dcf02677018a57f61cde787762911ea6ad0ba37e2b828293c3d1070b3bdba807084c4d22f19947b96510ec627da6e3b23d60d"
#     )


# # In this test we send to the device a transaction to trig a blind-signing flow
# # The transaction is short and will be sent in one chunk
# # We will ensure that the displayed information is correct by using screenshots comparison
# def test_sign_tx_short_tx_blind_sign(firmware, navigator, backend, scenario_navigator, test_name, default_screenshot_path):
#     if firmware.is_nano:
#         pytest.skip("Not supported on Nano devices")

#     # Use the app interface instead of raw interface
#     client = BoilerplateCommandSender(backend)
#     # The path used for this entire test
#     path: str = "m/44'/919'/0'/0/0"

#     # First we need to get the public key of the device in order to build the transaction
#     rapdu = client.get_public_key(path=path)
#     _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

#     # Create the transaction that will be sent to the device for signing
#     transaction = Transaction(
#         nonce=1,
#         to="0x0000000000000000000000000000000000000000",
#         value=0,
#         memo="Blind-sign"
#     ).serialize()

#     # Send the sign device instruction.
#     # As it requires on-screen validation, the function is asynchronous.
#     # It will yield the result when the navigation is done
#     with client.sign_tx(path=path, transaction=transaction):
#         navigator.navigate_and_compare(default_screenshot_path,
#                                         test_name+"/part1",
#                                         [NavInsID.USE_CASE_CHOICE_REJECT],
#                                         screen_change_after_last_instruction=False)

#         # Validate the on-screen request by performing the navigation appropriate for this device
#         scenario_navigator.review_approve()

#     # The device as yielded the result, parse it and ensure that the signature is correct
#     response = client.get_async_response().data
#     _, der_sig, _ = unpack_sign_tx_response(response)
#     assert check_signature_validity(public_key, der_sig, transaction)

# # In this test se send to the device a transaction to sign and validate it on screen
# # This test is mostly the same as the previous one but with different values.
# # In particular the long memo will force the transaction to be sent in multiple chunks
# def test_sign_tx_long_tx(backend, scenario_navigator):
#     # Use the app interface instead of raw interface
#     client = BoilerplateCommandSender(backend)
#     path: str = "m/44'/919'/0'/0/0"

#     rapdu = client.get_public_key(path=path)
#     _, public_key, _, _ = unpack_get_public_key_response(rapdu.data)

#     transaction = Transaction(
#         nonce=1,
#         to="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
#         value=666,
#         memo=("This is a very long memo. "
#               "It will force the app client to send the serialized transaction to be sent in chunk. "
#               "As the maximum chunk size is 255 bytes we will make this memo greater than 255 characters. "
#               "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed non risus. Suspendisse lectus tortor, dignissim sit amet, adipiscing nec, ultricies sed, dolor. Cras elementum ultrices diam.")
#     ).serialize()

#     with client.sign_tx(path=path, transaction=transaction):
#         scenario_navigator.review_approve()

#     response = client.get_async_response().data
#     _, der_sig, _ = unpack_sign_tx_response(response)
#     assert check_signature_validity(public_key, der_sig, transaction)


# # Transaction signature refused test
# # The test will ask for a transaction signature that will be refused on screen
# def test_sign_tx_refused(backend, scenario_navigator):
#     # Use the app interface instead of raw interface
#     client = BoilerplateCommandSender(backend)
#     path: str = "m/44'/919'/0'/0/0"

#     rapdu = client.get_public_key(path=path)
#     _, pub_key, _, _ = unpack_get_public_key_response(rapdu.data)

#     transaction = Transaction(
#         nonce=1,
#         to="0xde0b295669a9fd93d5f28d9ec85e40f4cb697bae",
#         value=666,
#         memo="This transaction will be refused by the user"
#     ).serialize()

#     with pytest.raises(ExceptionRAPDU) as e:
#         with client.sign_tx(path=path, transaction=transaction):
#             scenario_navigator.review_reject()

#     # Assert that we have received a refusal
#     assert e.value.status == Errors.SW_DENY
#     assert len(e.value.data) == 0
