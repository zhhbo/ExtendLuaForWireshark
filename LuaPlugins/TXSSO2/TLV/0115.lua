--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0115
-------- -------- -------- --------

SSO2::TLV_PacketMd5_0x115
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0115] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, 0, ">bufPacketMD5", 0x10 );
end