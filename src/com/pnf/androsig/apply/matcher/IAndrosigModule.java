/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.List;
import java.util.Map;
import java.util.Set;

import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnf.androsig.apply.model.MethodSignature;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexMethod;

/**
 * @author Cedric Lucas
 *
 */
public interface IAndrosigModule {
    /**
     * Start a new analysis pass
     * 
     * @param unit
     * @param dexHashCodeList
     * @param firstRound
     */
    void initNewPass(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound);

    Map<Integer, String> postProcessRenameClasses(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound);

    Map<Integer, String> postProcessRenameMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound);

    Set<MethodSignature> filterList(IDexUnit dex, IDexMethod eMethod, List<MethodSignature> results);
}
