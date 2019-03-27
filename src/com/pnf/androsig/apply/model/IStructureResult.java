/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.util.Map;

/**
 * @author Cedric Lucas
 *
 */
public interface IStructureResult {
    /**
     * Get method original signature through new signature
     * 
     * @return a Map (Key: method new signature. Value: method original signature)
     */
    Map<String, String> getMatchedMethods_new_orgPath();

    /**
     * Get class original signature through new signature
     * 
     * @return a Map (Key: class new signature. Value: class original signature)
     */
    Map<String, String> getMatchedClasses_new_orgPath();
}
