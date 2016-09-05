--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0310
-------- -------- -------- --------

SSO2::TLV_ServerAddress_0x310
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0310] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, 0, ">dwServerIP D" );
end