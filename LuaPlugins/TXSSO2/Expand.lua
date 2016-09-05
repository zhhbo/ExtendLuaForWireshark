--[=======[
-------- -------- -------- --------
  Tencent SSO 2  >>>> Expand
-------- -------- -------- --------

]=======]

local dissectors = require "TXSSO2/Dissectors";

local proto = require "TXSSO2/Proto";

local keychain = require "TXSSO2/KeyChain";

local fields = require "TXSSO2/Fields";
local fieldsex, fields = unpack( fields );

local tagname = require "TXSSO2/TagName";

--用于以seq关联数据包
local ref_tb = {};
function dissectors.ref_seq( root, pkg, buf, seq )
  local f = pkg.number;
  ref_tb[ seq ] = ref_tb[ seq ] or {};
  local tb = ref_tb[ seq ];
  tb[ f ] = tb[ f ] or true;

  for k, _ in pairs( tb ) do
    if k ~= f then
      root:add( fieldsex.refframe.field, k );
    end
  end
end

function dissectors.add( ... )
  return TreeAddEx( fieldsex, ... );
end

function dissectors.try_decrypt( root, pkg, buf, info, just_try )
  local data = buf:raw();

  local refkeyname,refkey, ds;
  for k, v in pairs( keychain ) do
    ds = TeanDecrypt( data, v );
    if ds ~= nil and #ds > 0 then
      refkeyname = k;
      refkey = v;
      break;
    end
  end

  if ds == nil or #ds == 0 then
    if not just_try then
      root:add( proto, buf(), string.format( info .. " [%04X] 解密失败！！！！", buf:len() ) );
    end
    return;
  end

  info = info .. string.format( " [%04X] >> [%04X]       With Key", buf:len(), #ds );
  
  local c, s, n = TXSSO2_AnalysisKeyName( refkeyname );
  if c then
    if n == tostring( pkg.number ) then
      info = info .. "    by frame self ↑↑↑";
      n = nil;
    else
      info = info .. ":" .. refkey:hex2str( true ) .. "       form FrameNum:" .. n;
    end
  else
    info = info .. "[" .. refkeyname .. "]:" .. refkey:hex2str( true );
    n = refkeyname:match( "^f(%d+)_" );
  end
  local t = root:add( proto, buf(), info );
  if n then
    t:add( fieldsex.keyframe.field, tonumber( n ) );
  end

  return t, ds;
end

function dissectors.dis_tlv( buf, pkg, root, t )
  local size = buf:len();
  local off = 0;

  local func = dissectors.tlv;
  if not func then
    root:add( proto, "Dissectors无TLV" );
  end

  while off < size do
    local tag = buf( off + 0, 2 ):uint();
    local len = buf( off + 2, 2 ):uint();
    local tags = tagname[ tag ] or "UnknownTag";
    local info = string.format( ">>TLV_%04X_%-20s     length : %04X", tag, tags, len );

    local tt = t:add( proto, buf( off, 2 + 2 + len ), info );
    local func = dissectors.tlv;
    if func then
      local tlv = buf( off + 2 + 2, len ):tvb();
      func = func[ tag ];
      if func then
        local b, ret = pcall( func, tlv, pkg, root, tt );
        if not b then
          root:add( proto, "TLV_" .. string.format( "%04X", tag ) .. "解析失败:" .. ret );
        else
          if ret < tlv:len() then
            TreeAddEx( fieldsex, tt, tlv, ret, ">unsolved" );
          end
        end
      else
        root:add( proto, tlv(), "Dissectors无对应TLV_" .. string.format( "%04X", tag ) );
      end
    end
    off = off + 2 + 2 + len;
  end
end