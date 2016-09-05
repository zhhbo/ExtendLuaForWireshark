--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0312
-------- -------- -------- --------

SSO2::TLV_Misc_Flag_0x312
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0312] = function( buf, pkg, root, t )
  return dissectors.add( t, buf, 0,
    ">*const_1 B",
    ">*const_0 D"
    );
end