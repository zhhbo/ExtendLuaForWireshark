--[=======[
-------- -------- -------- --------
         TreeAddEx操作
-------- -------- -------- --------
]=======]

--[=======[
●
    int       TreeAddEx                 (
                                        table     protofieldsex,
                                        TreeItem  root,
                                        Tvb       tvb,
                                        int       off,
                                        ...
                                        );                                 [-4+, +1, v]
        --根据要求自动生成树元素
        --protofieldsex为ProtoFieldEx返回的第一个表
        --不定参以 short_abbr, [size|format_function,] short_abbr, ... 形式提供
          当不提供size或format_function时，使用默认长度
          当指定field未有默认长度时，使用剩余的所有数据
          当指定size <= 0时，跳过不处理
          默认长度列表如下：          
            {
            uint8     = 1,
            uint16    = 2,
            uint24    = 3,
            uint32    = 4,
            uint64    = 8,
            int8      = 1,
            int16     = 2,
            int24     = 3,
            int32     = 4,
            int64     = 8,

            framenum  = 4,
            bool      = 1,
            absolute_time = 4,
            relative_time = 4,

            ipv4      = 4,
            ipv6      = 16,
            ether     = 6,
            float     = 4,
            double    = 8,
            };
        --abbr_name的第一个字符允许为'<'或'>'，用于标示field的大小端，默认大端
        --abbr_name允许以空格分隔注释。空格以后的所有数据被认为是注释而无视之
        --函数返回处理结束后的off
        --当提供format_function时，函数以如下形式调用
          format_function( buf, off, nil, tree_add_func, root, field );
          如果调用内部使用了tree_add_func，应返回off + size
          否则应返回formatted_string, size。
          处理将在其后自动调用tree_add_func( root, field, buf( off, size ), formatted_string );

        --允许指定abbr_name在protofieldsex中无匹配，此时有如下规则
          --当提供format_function时，函数以如下形式调用
            format_function( buf, off, nil, tree_add_func, root, field );
            如果调用内部使用了tree_add_func，应返回off + size
            否则应返回formatted_string, size。
            处理将在其后自动调用tree_add_func( root, buf( off, size), prefix_string .. formatted_string );
          --否则必须在空格后指定类型，支持类型参考FormatEx

        ex:
          off = TreeAddEx( fieldsex, root, tvb, off,
            "xxoo_b",                   --可识别的short_abbr，且可识别长度
            "xx", 2,                    --强制长度
            "xxoo_s", format_xxx        --可识别的short_abbr，但不可识别长度，需要自定义格式化
            );
          --生成效果大致如下：
          xxoo_b        Byte      :0x00
          xx            xx        :0x0000(0)
          xxoo_s        String    :xxxxxxxx

        ex:
          TreeAddEx( fieldsex, root, tvb, off,
            "*xxoo_b uint8",            --指定可识别的支持类型，不用后续指定大小
            "*xxoo_s string", 6,        --支持类型可识别，但强制指定大小
            "*xxoo_a", 5                --不指定类型，默认bytes
            );
          --生成效果大致如下：
          -             *xxoo_b   :0x00(0)
          -             *xxoo_s   :xxxxxx
          -             *xxoo_a   :##########
]=======]

-------- -------- -------- -------- 
local TypeDefaultSize =
  {
  uint8     = 1,
  uint16    = 2,
  uint24    = 3,
  uint32    = 4,
  uint64    = 8,
  int8      = 1,
  int16     = 2,
  int24     = 3,
  int32     = 4,
  int64     = 8,

  framenum  = 4,
  bool      = 1,
  absolute_time = 4,
  relative_time = 4,

  ipv4      = 4,
  ipv6      = 16,
  ether     = 6,
  float     = 4,
  double    = 8,
  };
-------- -------- -------- -------- 
local FieldShort =
  {
  b   = "uint8",
  w   = "uint16",
  d   = "uint32",
  q   = "uint64",
  a   = "bytes",
  s   = "string",

  B   = "uint8",
  W   = "uint16",
  D   = "uint32",
  Q   = "uint64",
  A   = "bytes",
  S   = "string",
  };

local function TreeAddEx_FormatIt( format_func, tvb, off, size, tree_add_func, root, field )
  local msg, size, limit_msg = format_func( tvb, off, size, tree_add_func, root, field );
  --如果格式化函数内部处理完毕，则不再继续
  if not size then
    size = msg;
    return size;
  end
  --size不对，也不进行后续处理
  if size < 0 then
    return off;
  end
  --否则进行默认添加
  --如果存在限长结果，则优先采用结果
  msg = limit_msg or msg;
  if "string" == type( field ) then
    tree_add_func( root, tvb( off, size ), field .. msg );
  else
    tree_add_func( root, field, tvb( off, size ), msg );
  end
  return off + size;
end

local function TreeAddEx_AddOne( arg, k, root, tvb, off, protofieldsex )
  --获取数据描述
  local abbr = arg[ k ];      k = k + 1;
  
  --判定大小端
  local tree_add_func = root.add;
  local isnet = abbr:sub(1, 1);
  if isnet == '<' then
    tree_add_func = root.add_le;
    abbr = abbr:sub( 2 );
  elseif isnet == '>' then
    abbr = abbr:sub( 2 );
  end

  --分离abbr与类型描述
  local abbr, format_type = abbr:match( "([^ ]+) *([^ ]*)" );

  --尝试类型简写转换
  if FieldShort[ format_type ] then
    format_type = FieldShort[ format_type ];
  end

  if format_type == "" then
    format_type = nil;
  end

  --空串忽略
  if not abbr or abbr == "" then
    return off, k;
  end

  --从fields里识别abbr，当abbr不可识别时，field为伪前缀
  local tb = protofieldsex[ abbr ];
  local field;
  if tb then
    field = tb.field;
  else
    field = string.format( protofieldsex.__fmt, "-", abbr:utf82s() ):s2utf8();
  end

  local next_abbr = arg[ k ];
  local next_abbr_type = type( next_abbr );
  --如果有指定格式化函数，则使用之
  if next_abbr_type == "function" then
    return TreeAddEx_FormatIt( next_abbr, tvb, off, nil, tree_add_func, root, field ), k + 1;
  end

  --开始优先处理可识别的abbr
  if tb then
    local abbr_size;
    if next_abbr_type == "number" then
      --abbr被指定大小
      local abbr_size = next_abbr;
      if abbr_size < 0 then
        return off, k + 1;
      end
      
      --写在abbr中的format_type优先，其次是exfunc
      format_type = format_type or tb.exfunc;
      if format_type and FormatEx[ format_type ] then
        return TreeAddEx_FormatIt( FormatEx[ format_type ], tvb, off, abbr_size, tree_add_func, root, field ), k + 1;
      end
      tree_add_func( root, field, tvb( off, abbr_size ) );
      return off + abbr_size, k + 1;
    end
    --如果未有指定大小，则尝试使用默认大小
    local abbr_size = TypeDefaultSize[ tb.types ];
    --使用abbr的标准类型
    if abbr_size then
      tree_add_func( root, field, tvb( off, abbr_size ) );
      return off + abbr_size, k;
    end

    --写在abbr中的format_type优先，其次是exfunc
    format_type = format_type or tb.exfunc;
    if format_type and FormatEx[ format_type ] then
      return TreeAddEx_FormatIt( FormatEx[ format_type ], tvb, off, abbr_size, tree_add_func, root, field ), k;
    end

    tree_add_func( root, field, tvb( off ) );
    return tvb:len(), k;
  end

  --abbr不可识别时，除非另外指定格式化函数，否则必须指定类型，且类型可格式化
  if not format_type then
    return error( "abbr:" .. abbr .. " no fixed and no type" );
  end
  local format_func = FormatEx[ format_type ];
  if not format_func then
    return error( "abbr:" .. abbr .. ", type:" .. format_type .. " no fixed and type unknown" );
  end

  --如果有指定大小，则使用指定大小
  local abbr_size;
  if next_abbr_type == "number" then
    abbr_size = next_abbr;
    k = k + 1;
  end

  return TreeAddEx_FormatIt( format_func, tvb, off, abbr_size, tree_add_func, root, field ), k;
end

function TreeAddEx( protofieldsex, root, tvb, off, ... )
  local off = off or 0;
  local arg = { ... };

  local k = 1;
  while k <= #arg do
    off, k = TreeAddEx_AddOne( arg, k, root, tvb, off, protofieldsex );
    if off >= tvb:len() then
      break;
    end
  end
  return off;
end