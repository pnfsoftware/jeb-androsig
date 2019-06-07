/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.List;

import com.pnfsoftware.jeb.core.units.code.android.IDexUnit;
import com.pnfsoftware.jeb.core.units.code.android.dex.IDexClass;

/**
 * @author Cedric Lucas
 *
 */
interface IMatcherValidation {
    /**
     * Indicate if class is valid enough to be mapped
     * 
     * @param unit
     * @param eClass
     * @param matchedMethods
     * @return error message, null if successful
     */
    String f(IDexUnit unit, IDexClass eClass, List<Integer> matchedMethods);
}
