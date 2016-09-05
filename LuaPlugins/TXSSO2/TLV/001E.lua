--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 001E
-------- -------- -------- --------

SSO2::TLV_GTKey_TGTGT_0x1e
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x001E] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, 0, ">bufTGTGTKey", 0x10 );
end