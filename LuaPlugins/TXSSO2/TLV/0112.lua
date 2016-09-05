--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0112
-------- -------- -------- --------

SSO2::TLV_SigIP2_0x112
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0112] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, 0, ">bufSigClientAddr" );
end