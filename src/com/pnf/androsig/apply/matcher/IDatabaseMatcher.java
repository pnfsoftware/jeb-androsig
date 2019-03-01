/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.Map;

import com.pnf.androsig.apply.model.DexHashcodeList;
import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;

/**
 * @author Cedric Lucas
 *
 */
public interface IDatabaseMatcher {
    void storeMatchedClassesAndMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound);

    /**
     * Get all matched classes.
     * 
     * @return a Map (key: index of a class. Value: a set of all matched classes(path))
     */
    Map<Integer, String> getMatchedClasses();

    /**
     * Get all matched methods.
     * 
     * @return a Map (Key: index of a method. Value: actual name of a method)
     */
    Map<Integer, String> getMatchedMethods();

    Map<Integer, Map<Integer, Integer>> getApkCallerLists();
    DatabaseMatcherParameters getParameters();

    Map<Integer, String> postProcessRenameClasses(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound);

    Map<Integer, String> postProcessRenameMethods(IDexUnit unit, DexHashcodeList dexHashCodeList, boolean firstRound);

    ISignatureMetrics getSignatureMetrics();
}
