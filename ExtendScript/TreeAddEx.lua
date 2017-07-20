--[=======[
-------- -------- -------- --------
         TreeAddEx����
-------- -------- -------- --------
]=======]

--[=======[
��
    int       TreeAddEx                 (
                                        table     protofieldsex,
                                        TreeItem  root,
                                        Tvb       tvb,
                                        int       off,
                                        ...
                                        );                                 [-4+, +1, v]
        --����Ҫ���Զ�������Ԫ��
        --protofieldsexΪProtoFieldEx���صĵ�һ����
        --�������� short_abbr, [size|format_function,] short_abbr, ... ��ʽ�ṩ
          �����ṩsize��format_functionʱ��ʹ��Ĭ�ϳ���
          ��ָ��fieldδ��Ĭ�ϳ���ʱ��ʹ��ʣ�����������
          ��ָ��size <= 0ʱ������������
          Ĭ�ϳ����б����£�          
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
        --abbr_name�ĵ�һ���ַ�����Ϊ'<'��'>'�����ڱ�ʾfield�Ĵ�С�ˣ�Ĭ�ϴ��
        --abbr_name�����Կո�ָ�ע�͡��ո��Ժ���������ݱ���Ϊ��ע�Ͷ�����֮
        --�������ش���������off
        --���ṩformat_functionʱ��������������ʽ����
          format_function( buf, off, nil, tree_add_func, root, field );
          ��������ڲ�ʹ����tree_add_func��Ӧ����off + size
          ����Ӧ����formatted_string, size��
          ����������Զ�����tree_add_func( root, field, buf( off, size ), formatted_string );

        --����ָ��abbr_name��protofieldsex����ƥ�䣬��ʱ�����¹���
          --���ṩformat_functionʱ��������������ʽ����
            format_function( buf, off, nil, tree_add_func, root, field );
            ��������ڲ�ʹ����tree_add_func��Ӧ����off + size
            ����Ӧ����formatted_string, size��
            ����������Զ�����tree_add_func( root, buf( off, size), prefix_string .. formatted_string );
          --��������ڿո��ָ�����ͣ�֧�����Ͳο�FormatEx

        ex:
          off = TreeAddEx( fieldsex, root, tvb, off,
            "xxoo_b",                   --��ʶ���short_abbr���ҿ�ʶ�𳤶�
            "xx", 2,                    --ǿ�Ƴ���
            "xxoo_s", format_xxx        --��ʶ���short_abbr��������ʶ�𳤶ȣ���Ҫ�Զ����ʽ��
            );
          --����Ч���������£�
          xxoo_b        Byte      :0x00
          xx            xx        :0x0000(0)
          xxoo_s        String    :xxxxxxxx

        ex:
          TreeAddEx( fieldsex, root, tvb, off,
            "*xxoo_b uint8",            --ָ����ʶ���֧�����ͣ����ú���ָ����С
            "*xxoo_s string", 6,        --֧�����Ϳ�ʶ�𣬵�ǿ��ָ����С
            "*xxoo_a", 5                --��ָ�����ͣ�Ĭ��bytes
            );
          --����Ч���������£�
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
  --�����ʽ�������ڲ�������ϣ����ټ���
  if not size then
    size = msg;
    return size;
  end
  --size���ԣ�Ҳ�����к�������
  if size < 0 then
    return off;
  end
  --�������Ĭ�����
  --��������޳�����������Ȳ��ý��
  msg = limit_msg or msg;
  if "string" == type( field ) then
    tree_add_func( root, tvb( off, size ), field .. msg );
  else
    tree_add_func( root, field, tvb( off, size ), msg );
  end
  return off + size;
end

local function TreeAddEx_AddOne( arg, k, root, tvb, off, protofieldsex )
  --��ȡ��������
  local abbr = arg[ k ];      k = k + 1;
  
  --�ж���С��
  local tree_add_func = root.add;
  local isnet = abbr:sub(1, 1);
  if isnet == '<' then
    tree_add_func = root.add_le;
    abbr = abbr:sub( 2 );
  elseif isnet == '>' then
    abbr = abbr:sub( 2 );
  end

  --����abbr����������
  local abbr, format_type = abbr:match( "([^ ]+) *([^ ]*)" );

  --�������ͼ�дת��
  if FieldShort[ format_type ] then
    format_type = FieldShort[ format_type ];
  end

  if format_type == "" then
    format_type = nil;
  end

  --�մ�����
  if not abbr or abbr == "" then
    return off, k;
  end

  --��fields��ʶ��abbr����abbr����ʶ��ʱ��fieldΪαǰ׺
  local tb = protofieldsex[ abbr ];
  local field;
  if tb then
    field = tb.field;
  else
    field = string.format( protofieldsex.__fmt, "-", abbr:utf82s() ):s2utf8();
  end

  local next_abbr = arg[ k ];
  local next_abbr_type = type( next_abbr );
  --�����ָ����ʽ����������ʹ��֮
  if next_abbr_type == "function" then
    return TreeAddEx_FormatIt( next_abbr, tvb, off, nil, tree_add_func, root, field ), k + 1;
  end

  --��ʼ���ȴ����ʶ���abbr
  if tb then
    local abbr_size;
    if next_abbr_type == "number" then
      --abbr��ָ����С
      local abbr_size = next_abbr;
      if abbr_size < 0 then
        return off, k + 1;
      end
      
      --д��abbr�е�format_type���ȣ������exfunc
      format_type = format_type or tb.exfunc;
      if format_type and FormatEx[ format_type ] then
        return TreeAddEx_FormatIt( FormatEx[ format_type ], tvb, off, abbr_size, tree_add_func, root, field ), k + 1;
      end
      tree_add_func( root, field, tvb( off, abbr_size ) );
      return off + abbr_size, k + 1;
    end
    --���δ��ָ����С������ʹ��Ĭ�ϴ�С
    local abbr_size = TypeDefaultSize[ tb.types ];
    --ʹ��abbr�ı�׼����
    if abbr_size then
      tree_add_func( root, field, tvb( off, abbr_size ) );
      return off + abbr_size, k;
    end

    --д��abbr�е�format_type���ȣ������exfunc
    format_type = format_type or tb.exfunc;
    if format_type and FormatEx[ format_type ] then
      return TreeAddEx_FormatIt( FormatEx[ format_type ], tvb, off, abbr_size, tree_add_func, root, field ), k;
    end

    tree_add_func( root, field, tvb( off ) );
    return tvb:len(), k;
  end

  --abbr����ʶ��ʱ����������ָ����ʽ���������������ָ�����ͣ������Ϳɸ�ʽ��
  if not format_type then
    return error( "abbr:" .. abbr .. " no fixed and no type" );
  end
  local format_func = FormatEx[ format_type ];
  if not format_func then
    return error( "abbr:" .. abbr .. ", type:" .. format_type .. " no fixed and type unknown" );
  end

  --�����ָ����С����ʹ��ָ����С
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