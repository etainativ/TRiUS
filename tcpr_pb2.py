# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: tcpr.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='tcpr.proto',
  package='',
  syntax='proto3',
  serialized_pb=_b('\n\ntcpr.proto\"Z\n\nfour_tuple\x12\x10\n\x08local_ip\x18\x01 \x01(\t\x12\x11\n\tremote_ip\x18\x02 \x01(\t\x12\x12\n\nlocal_port\x18\x03 \x01(\r\x12\x13\n\x0bremote_port\x18\x04 \x01(\r\"s\n\x08tcpr_set\x12\x1f\n\nconnection\x18\x01 \x01(\x0b\x32\x0b.four_tuple\x12\x14\n\x0csack_enabled\x18\x02 \x01(\r\x12\x18\n\x10max_segment_size\x18\x03 \x01(\r\x12\x16\n\x0ewindow_scaling\x18\x04 \x01(\r\"0\n\rtcpr_get_init\x12\x1f\n\nconnection\x18\x01 \x01(\x0b\x32\x0b.four_tuple\"/\n\x0ctcpr_get_ack\x12\x1f\n\nconnection\x18\x01 \x01(\x0b\x32\x0b.four_tuple\"\x0f\n\rtcpr_get_list\"8\n\x16tcpr_get_list_response\x12\x1e\n\x0b\x63onnections\x18\x01 \x03(\x0b\x32\t.tcpr_set\",\n\x11tcpr_set_response\x12\x17\n\x06status\x18\x01 \x01(\x0e\x32\x07.status\"\x8e\x01\n\x16tcpr_get_init_response\x12\x17\n\x06status\x18\x01 \x01(\x0e\x32\x07.status\x12\x13\n\x0binitial_seq\x18\x02 \x01(\r\x12\x14\n\x0csack_enabled\x18\x03 \x01(\r\x12\x18\n\x10max_segment_size\x18\x04 \x01(\r\x12\x16\n\x0ewindow_scaling\x18\x05 \x01(\r\"E\n\x15tcpr_get_ack_response\x12\x17\n\x06status\x18\x01 \x01(\x0e\x32\x07.status\x12\x13\n\x0b\x63urrent_ack\x18\x02 \x01(\r\"\xe1\x02\n\x04tcpr\x12\"\n\x08get_init\x18\x01 \x01(\x0b\x32\x0e.tcpr_get_initH\x00\x12\x34\n\x11get_init_response\x18\x02 \x01(\x0b\x32\x17.tcpr_get_init_responseH\x00\x12 \n\x07get_ack\x18\x03 \x01(\x0b\x32\r.tcpr_get_ackH\x00\x12\x32\n\x10get_ack_response\x18\x04 \x01(\x0b\x32\x16.tcpr_get_ack_responseH\x00\x12\"\n\x08get_list\x18\x05 \x01(\x0b\x32\x0e.tcpr_get_listH\x00\x12\x34\n\x11get_list_response\x18\x06 \x01(\x0b\x32\x17.tcpr_get_list_responseH\x00\x12\x18\n\x03set\x18\x07 \x01(\x0b\x32\t.tcpr_setH\x00\x12*\n\x0cset_response\x18\x08 \x01(\x0b\x32\x12.tcpr_set_responseH\x00\x42\t\n\x07message*J\n\x06status\x12\x0b\n\x07SUCCESS\x10\x00\x12\x11\n\rFAILED_EXISTS\x10\x01\x12\x14\n\x10\x46\x41ILED_NOT_FOUND\x10\x02\x12\n\n\x06\x46\x41ILED\x10\x03\x62\x06proto3')
)
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

_STATUS = _descriptor.EnumDescriptor(
  name='status',
  full_name='status',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='SUCCESS', index=0, number=0,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='FAILED_EXISTS', index=1, number=1,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='FAILED_NOT_FOUND', index=2, number=2,
      options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='FAILED', index=3, number=3,
      options=None,
      type=None),
  ],
  containing_type=None,
  options=None,
  serialized_start=1015,
  serialized_end=1089,
)
_sym_db.RegisterEnumDescriptor(_STATUS)

status = enum_type_wrapper.EnumTypeWrapper(_STATUS)
SUCCESS = 0
FAILED_EXISTS = 1
FAILED_NOT_FOUND = 2
FAILED = 3



_FOUR_TUPLE = _descriptor.Descriptor(
  name='four_tuple',
  full_name='four_tuple',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='local_ip', full_name='four_tuple.local_ip', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='remote_ip', full_name='four_tuple.remote_ip', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='local_port', full_name='four_tuple.local_port', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='remote_port', full_name='four_tuple.remote_port', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=14,
  serialized_end=104,
)


_TCPR_SET = _descriptor.Descriptor(
  name='tcpr_set',
  full_name='tcpr_set',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='connection', full_name='tcpr_set.connection', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sack_enabled', full_name='tcpr_set.sack_enabled', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='max_segment_size', full_name='tcpr_set.max_segment_size', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='window_scaling', full_name='tcpr_set.window_scaling', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=106,
  serialized_end=221,
)


_TCPR_GET_INIT = _descriptor.Descriptor(
  name='tcpr_get_init',
  full_name='tcpr_get_init',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='connection', full_name='tcpr_get_init.connection', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=223,
  serialized_end=271,
)


_TCPR_GET_ACK = _descriptor.Descriptor(
  name='tcpr_get_ack',
  full_name='tcpr_get_ack',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='connection', full_name='tcpr_get_ack.connection', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=273,
  serialized_end=320,
)


_TCPR_GET_LIST = _descriptor.Descriptor(
  name='tcpr_get_list',
  full_name='tcpr_get_list',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=322,
  serialized_end=337,
)


_TCPR_GET_LIST_RESPONSE = _descriptor.Descriptor(
  name='tcpr_get_list_response',
  full_name='tcpr_get_list_response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='connections', full_name='tcpr_get_list_response.connections', index=0,
      number=1, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=339,
  serialized_end=395,
)


_TCPR_SET_RESPONSE = _descriptor.Descriptor(
  name='tcpr_set_response',
  full_name='tcpr_set_response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='tcpr_set_response.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=397,
  serialized_end=441,
)


_TCPR_GET_INIT_RESPONSE = _descriptor.Descriptor(
  name='tcpr_get_init_response',
  full_name='tcpr_get_init_response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='tcpr_get_init_response.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='initial_seq', full_name='tcpr_get_init_response.initial_seq', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='sack_enabled', full_name='tcpr_get_init_response.sack_enabled', index=2,
      number=3, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='max_segment_size', full_name='tcpr_get_init_response.max_segment_size', index=3,
      number=4, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='window_scaling', full_name='tcpr_get_init_response.window_scaling', index=4,
      number=5, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=444,
  serialized_end=586,
)


_TCPR_GET_ACK_RESPONSE = _descriptor.Descriptor(
  name='tcpr_get_ack_response',
  full_name='tcpr_get_ack_response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='status', full_name='tcpr_get_ack_response.status', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='current_ack', full_name='tcpr_get_ack_response.current_ack', index=1,
      number=2, type=13, cpp_type=3, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=588,
  serialized_end=657,
)


_TCPR = _descriptor.Descriptor(
  name='tcpr',
  full_name='tcpr',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='get_init', full_name='tcpr.get_init', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='get_init_response', full_name='tcpr.get_init_response', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='get_ack', full_name='tcpr.get_ack', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='get_ack_response', full_name='tcpr.get_ack_response', index=3,
      number=4, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='get_list', full_name='tcpr.get_list', index=4,
      number=5, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='get_list_response', full_name='tcpr.get_list_response', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='set', full_name='tcpr.set', index=6,
      number=7, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    _descriptor.FieldDescriptor(
      name='set_response', full_name='tcpr.set_response', index=7,
      number=8, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='message', full_name='tcpr.message',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=660,
  serialized_end=1013,
)

_TCPR_SET.fields_by_name['connection'].message_type = _FOUR_TUPLE
_TCPR_GET_INIT.fields_by_name['connection'].message_type = _FOUR_TUPLE
_TCPR_GET_ACK.fields_by_name['connection'].message_type = _FOUR_TUPLE
_TCPR_GET_LIST_RESPONSE.fields_by_name['connections'].message_type = _TCPR_SET
_TCPR_SET_RESPONSE.fields_by_name['status'].enum_type = _STATUS
_TCPR_GET_INIT_RESPONSE.fields_by_name['status'].enum_type = _STATUS
_TCPR_GET_ACK_RESPONSE.fields_by_name['status'].enum_type = _STATUS
_TCPR.fields_by_name['get_init'].message_type = _TCPR_GET_INIT
_TCPR.fields_by_name['get_init_response'].message_type = _TCPR_GET_INIT_RESPONSE
_TCPR.fields_by_name['get_ack'].message_type = _TCPR_GET_ACK
_TCPR.fields_by_name['get_ack_response'].message_type = _TCPR_GET_ACK_RESPONSE
_TCPR.fields_by_name['get_list'].message_type = _TCPR_GET_LIST
_TCPR.fields_by_name['get_list_response'].message_type = _TCPR_GET_LIST_RESPONSE
_TCPR.fields_by_name['set'].message_type = _TCPR_SET
_TCPR.fields_by_name['set_response'].message_type = _TCPR_SET_RESPONSE
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['get_init'])
_TCPR.fields_by_name['get_init'].containing_oneof = _TCPR.oneofs_by_name['message']
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['get_init_response'])
_TCPR.fields_by_name['get_init_response'].containing_oneof = _TCPR.oneofs_by_name['message']
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['get_ack'])
_TCPR.fields_by_name['get_ack'].containing_oneof = _TCPR.oneofs_by_name['message']
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['get_ack_response'])
_TCPR.fields_by_name['get_ack_response'].containing_oneof = _TCPR.oneofs_by_name['message']
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['get_list'])
_TCPR.fields_by_name['get_list'].containing_oneof = _TCPR.oneofs_by_name['message']
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['get_list_response'])
_TCPR.fields_by_name['get_list_response'].containing_oneof = _TCPR.oneofs_by_name['message']
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['set'])
_TCPR.fields_by_name['set'].containing_oneof = _TCPR.oneofs_by_name['message']
_TCPR.oneofs_by_name['message'].fields.append(
  _TCPR.fields_by_name['set_response'])
_TCPR.fields_by_name['set_response'].containing_oneof = _TCPR.oneofs_by_name['message']
DESCRIPTOR.message_types_by_name['four_tuple'] = _FOUR_TUPLE
DESCRIPTOR.message_types_by_name['tcpr_set'] = _TCPR_SET
DESCRIPTOR.message_types_by_name['tcpr_get_init'] = _TCPR_GET_INIT
DESCRIPTOR.message_types_by_name['tcpr_get_ack'] = _TCPR_GET_ACK
DESCRIPTOR.message_types_by_name['tcpr_get_list'] = _TCPR_GET_LIST
DESCRIPTOR.message_types_by_name['tcpr_get_list_response'] = _TCPR_GET_LIST_RESPONSE
DESCRIPTOR.message_types_by_name['tcpr_set_response'] = _TCPR_SET_RESPONSE
DESCRIPTOR.message_types_by_name['tcpr_get_init_response'] = _TCPR_GET_INIT_RESPONSE
DESCRIPTOR.message_types_by_name['tcpr_get_ack_response'] = _TCPR_GET_ACK_RESPONSE
DESCRIPTOR.message_types_by_name['tcpr'] = _TCPR
DESCRIPTOR.enum_types_by_name['status'] = _STATUS

four_tuple = _reflection.GeneratedProtocolMessageType('four_tuple', (_message.Message,), dict(
  DESCRIPTOR = _FOUR_TUPLE,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:four_tuple)
  ))
_sym_db.RegisterMessage(four_tuple)

tcpr_set = _reflection.GeneratedProtocolMessageType('tcpr_set', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_SET,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_set)
  ))
_sym_db.RegisterMessage(tcpr_set)

tcpr_get_init = _reflection.GeneratedProtocolMessageType('tcpr_get_init', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_GET_INIT,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_get_init)
  ))
_sym_db.RegisterMessage(tcpr_get_init)

tcpr_get_ack = _reflection.GeneratedProtocolMessageType('tcpr_get_ack', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_GET_ACK,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_get_ack)
  ))
_sym_db.RegisterMessage(tcpr_get_ack)

tcpr_get_list = _reflection.GeneratedProtocolMessageType('tcpr_get_list', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_GET_LIST,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_get_list)
  ))
_sym_db.RegisterMessage(tcpr_get_list)

tcpr_get_list_response = _reflection.GeneratedProtocolMessageType('tcpr_get_list_response', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_GET_LIST_RESPONSE,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_get_list_response)
  ))
_sym_db.RegisterMessage(tcpr_get_list_response)

tcpr_set_response = _reflection.GeneratedProtocolMessageType('tcpr_set_response', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_SET_RESPONSE,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_set_response)
  ))
_sym_db.RegisterMessage(tcpr_set_response)

tcpr_get_init_response = _reflection.GeneratedProtocolMessageType('tcpr_get_init_response', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_GET_INIT_RESPONSE,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_get_init_response)
  ))
_sym_db.RegisterMessage(tcpr_get_init_response)

tcpr_get_ack_response = _reflection.GeneratedProtocolMessageType('tcpr_get_ack_response', (_message.Message,), dict(
  DESCRIPTOR = _TCPR_GET_ACK_RESPONSE,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr_get_ack_response)
  ))
_sym_db.RegisterMessage(tcpr_get_ack_response)

tcpr = _reflection.GeneratedProtocolMessageType('tcpr', (_message.Message,), dict(
  DESCRIPTOR = _TCPR,
  __module__ = 'tcpr_pb2'
  # @@protoc_insertion_point(class_scope:tcpr)
  ))
_sym_db.RegisterMessage(tcpr)


# @@protoc_insertion_point(module_scope)
