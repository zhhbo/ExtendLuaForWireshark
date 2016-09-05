--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> TLV >>>> 0108
-------- -------- -------- --------

SSO2::TLV_AccountBasicInfo_0x108
]=======]

local dissectors = require "TXSSO2/Dissectors";

dissectors.tlv = dissectors.tlv or {};

local proto = require "TXSSO2/Proto";

dissectors.tlv[0x0108] = function( buf, pkg, root, t )
  local off = 0;
  local ver = buf( off, 2 ):uint();
  off = dissectors.add( t, buf, off, ">wTlvVer W" );
  if ver == 0x0001 then
    local ss, size = FormatEx.wxline_string( buf, off );
    local tt = t:add( proto, buf( off, size ),
      string.format( "bufAccountBasicInfo    帐户基本信息   (%04X)", #ss )
      );
    local data = buf( off, size ):tvb();
    local oo = 2;
    do
      local sss, size = FormatEx.wxline_string( data, oo );
      local ttt = tt:add( proto, data( oo, size ),
        string.format( "bufInAccountValue   (%04X)", #sss )
        );
      
      local data = data( oo, size ):tvb();
      local ooo = dissectors.add( ttt, data, 2,
        ">wSSO_Account_wFaceIndex     W",
        ">strSSO_Account_strNickName  bxline_string",
        ">cSSO_Account_cGender        B",
        ">dwSSO_Account_dwUinFlag     D",
        ">cSSO_Account_cAge           B",
        ">unsolved"
        );
      oo = oo + ooo;
    end
    oo = dissectors.add( tt, data, oo,
      ">bufSTOther                wxline_bytes",
      ">unsolved"
      );
    off = off + oo;
  end
  return off;
end