package com.pnf.androsig.apply.util;

import com.pnf.androsig.apply.model.DexMetadataGroupClass;
import com.pnf.androsig.apply.model.DexMetadataGroupMethod;
import com.pnf.androsig.apply.model.IStructureResult;
import com.pnfsoftware.jeb.core.units.IMetadataGroup;
import com.pnfsoftware.jeb.core.units.MetadataGroupType;
import com.pnfsoftware.jeb.core.units.code.ICodeUnit;

public class MetadataGroupHandler {

    /**
     * Create method code group.
     * 
     * @param unit mandatory target unit
     * @param struInfo structureInfo Object which contains structure informations
     */

    public static void createCodeGroupMethod(ICodeUnit unit, IStructureResult struRes) {
        IMetadataGroup grp = new DexMetadataGroupMethod("codeAnalysisMethods", MetadataGroupType.CLASSID, struRes);
        unit.getMetadataManager().addGroup(grp);
    }

    /**
     * Get method code group (codeAnalysisMethods).
     * 
     * @param unit mandatory target unit
     * @return IMetadataGroup
     */
    public static IMetadataGroup getCodeGroupMethod(ICodeUnit unit) {
        return unit.getMetadataManager().getGroupByName("codeAnalysisMethods");
    }

    /**
     * Create class code group(matched classes).
     * 
     * @param unit mandatory target unit
     * @param struInfo StructureInfo Object which contains structure informations
     */
    public static void createCodeGroupClass(ICodeUnit unit, IStructureResult struRes) {
        IMetadataGroup grp = new DexMetadataGroupClass("codeAnalysisClasses", MetadataGroupType.CLASSID, struRes);
        unit.getMetadataManager().addGroup(grp);
    }

    /**
     * Get class code group (codeAnalysisClasses).
     * 
     * @param unit mandatory target unit
     * @return IMetadataGroup
     */
    public static IMetadataGroup getCodeGroupClass(ICodeUnit unit) {
        return unit.getMetadataManager().getGroupByName("codeAnalysisClasses");
    }
}
