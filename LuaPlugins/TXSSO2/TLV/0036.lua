--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0036
-------- -------- -------- --------

SSO2::TLV_LoginReason_0x36
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

dissectors.tlv[0x0036] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    off = dissectors.add( t, buf, off,
      ">*const_1 W",
      ">*const_0 D",
      ">*const_0 W"
      );
  elseif ver == 0x0002 then
    off = dissectors.add( t, buf, off,
      ">*const_1 W",
      ">*const_0 D",
      ">*const_0 W",
      ">*const_0 W",
      ">*const_0 D",
      ">*const_0 B",
      ">*const_0 B"
      );
  end
  return off;
end