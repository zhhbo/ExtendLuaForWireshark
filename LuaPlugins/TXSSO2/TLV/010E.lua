local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x010E] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local sss = buf( off, 2 ):uint();
    local tt = t:add( proto, buf( off, 2 + sss ), string.format( "info (%04X)", sss ) );
    local data = buf( off, 2 + sss ):tvb();
    local oo = dissectors.add( tt, data, 2,
      ">dwUinLevel            D",
      ">dwUinLevelEx          D",
      ">buf24byteSignature    wxline_bytes",
      ">buf32byteValueAddedSignature wxline_bytes",
      ">buf12byteUserBitmap   wxline_bytes",
      ">unsolved"
      );
    off = off + oo;
  end
  return off;
end