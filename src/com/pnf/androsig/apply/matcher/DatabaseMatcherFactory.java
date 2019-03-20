/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.Map;

import com.pnf.androsig.apply.model.DatabaseReference;

/**
 * @author Cedric Lucas
 *
 */
public class DatabaseMatcherFactory {

    public static IDatabaseMatcher build(DatabaseMatcherParameters params, DatabaseReference ref) {
        return new DatabaseMatcher2(params, ref);
    }

    public static IDatabaseMatcher build(Map<String, String> executionOptions, DatabaseReference ref) {
        return build(DatabaseMatcherParameters.parseParameters(executionOptions), ref);
    }
}
