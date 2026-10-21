import gdb
import gdb.printing
import re

class EnumResolver:
    """枚举解析器，从GDB调试信息中动态获取枚举值"""
    
    _cache = {}
    
    @classmethod
    def get_enum_mapping_in_order(cls, enum_type_name):
        """获取枚举类型名称到值的映射"""
        if enum_type_name in cls._cache:
            return cls._cache[enum_type_name]
        
        try:
            # 尝试获取枚举类型
            enum_type = gdb.lookup_type(enum_type_name)
            if enum_type.code != gdb.TYPE_CODE_ENUM:
                return {}
            
            # 获取枚举的所有字段
            mapping = {}
            for field in enum_type.fields():
                mapping[field.name] = field.enumval

            # 按枚举值排序,，返回的是列表，不是字典
            ordered_mapping = sorted(mapping.items(), key=lambda x: x[1])

            cls._cache[enum_type_name] = ordered_mapping
            return ordered_mapping
        except:
            # 如果查找失败，返回空映射
            raise gdb.GdbError(f"无法获取枚举{enum_type_name}相关信息")
    
    @classmethod
    def get_enum_name(cls, enum_type_name, value):
        """根据枚举值获取名称"""
        mapping = cls.get_enum_mapping_in_order(enum_type_name)
        for name, val in mapping:
            if val == value:
                return name
        return f"UNKNOWN({value})"


class AntaresTypePrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_type_e", int(self.val))

class AntaresCspPrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_csp_e", int(self.val))

class AntaresPicStructurePrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_pic_structure_e", int(self.val))

class AntaresPictureTypePrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_picture_type_e", int(self.val))

class AntaresSampleFmtPrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_sample_fmt_e", int(self.val))

class AntaresChannelLayputPrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_channel_layout_e", int(self.val))

class AntaresCodecIdPrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_codec_id_e", int(self.val))

class AntaresColorPrimariesPrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_ColorPrimaries", int(self.val))

class AntaresColorTransferPrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_ColorTransfer", int(self.val))

class AntaresColorMatrixPrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_ColorMatrix", int(self.val))

class AntaresColorRangePrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_color_range_", int(self.val))

class AntaresInfoTypePrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return EnumResolver.get_enum_name("Antares_info_type_e", int(self.val))


class DynamicArrayPrinter:
    """动态数组打印机基类"""
    
    _cache ={
            "FRAME_CSP": AntaresCspPrinter,
            "FRAME_CODEC_ID": AntaresCodecIdPrinter, 
            "FRAME_CHANNEL_LAYOUT": AntaresChannelLayputPrinter,
            "FRAME_PIC_STRUCTURE": AntaresPicStructurePrinter,
            "FRAME_PIC_TYPE": AntaresPictureTypePrinter,
            "FRAME_SAMPLE_FMT": AntaresSampleFmtPrinter,
            "FRAME_COLOR_PRIMARIES": AntaresColorPrimariesPrinter,
            "FRAME_COLOR_TRANSFER": AntaresColorTransferPrinter,
            "FRAME_COLOR_MATRIX": AntaresColorMatrixPrinter,
            "FRAME_COLOR_RANGE": AntaresColorRangePrinter,
            "FRAME_INFO_TYPE":AntaresInfoTypePrinter
    }

    def __init__(self, val, enum_type_name, array_size):
        self.val = val
        self.enum_type_name = enum_type_name
        self.array_size = array_size
        
    def to_string(self):
        prop_mapping = EnumResolver.get_enum_mapping_in_order(self.enum_type_name)
        result = []
        array_ptr = self.val
        for prop_name, enumval in prop_mapping:
            if(prop_name.startswith('MAX_FRAME_')):
                continue
            if enumval >= self.array_size:
                raise gdb.GdbError(f"不合法的enum {self.enum_type_name}定义, array size={self.array_size}, item {prop_name}={enumval}")
            element_val = int(array_ptr[enumval])
            if prop_name in self._cache:
                printer_class = self._cache[prop_name]
                readable_val=printer_class(element_val).to_string()
            else:
                readable_val=element_val
            result.append("{}: {}".format("'" + prop_name + "'",readable_val))
        
        return "{" + ",  ".join(result) + "}"

class Prop32Printer(DynamicArrayPrinter):
    def __init__(self, val):
        # 从调试信息获取数组大小
        array_type = val.type
        if array_type.code == gdb.TYPE_CODE_ARRAY:
            array_size = int(array_type.range()[1]) + 1
            super().__init__(val, "frame_property_e", array_size)
        else:
            raise gdb.GdbError("prop32_ not TYPE_CODE_ARRAY")

class Prop64Printer(DynamicArrayPrinter):
    def __init__(self, val):
        array_type = val.type
        if array_type.code == gdb.TYPE_CODE_ARRAY:
            array_size = int(array_type.range()[1]) + 1
            super().__init__(val, "frame_property64_e", array_size)
        else:
            raise gdb.GdbError("prop64_ not TYPE_CODE_ARRAY")

class AntaresFramePrinter:
    def __init__(self, val):
        self.val = val
    
    def to_string(self):
        return "AntaresFrame"
    
    def children(self):
        result = []
        
        # type_
        type_val = self.val['type_']
        result.append(("type", AntaresTypePrinter(type_val).to_string()))
        
        # prop32_
        prop32_val = self.val['prop32_']
        result.append(("prop32", Prop32Printer(prop32_val).to_string()))
        
        # prop64_
        prop64_val = self.val['prop64_']
        result.append(("prop64", Prop64Printer(prop64_val).to_string()))
        
        return iter(result)

#向gdb注册自定义的pretty-printer：
def lookup_AntaresFrame(val):
    if str(val.type) == "AntaresFrame":
        return AntaresFramePrinter(val)
    if str(val.type) == "Antares_frame_handle":
        AntaresFrame_pointer = val.cast(gdb.lookup_type("AntaresFrame").pointer())
        deref_val=AntaresFrame_pointer.dereference() 
        return AntaresFramePrinter(deref_val)
    return None
gdb.pretty_printers.append(lookup_AntaresFrame)

