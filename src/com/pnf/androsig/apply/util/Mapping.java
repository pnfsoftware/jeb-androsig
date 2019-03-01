/*
 * JEB Copyright PNF Software, Inc.
 * 
 *     https://www.pnfsoftware.com
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pnf.androsig.apply.util;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * Store class mapping and method mapping and mainly for serialization.
 * 
 * @author Ruoxiao Wang
 *
 */
public class Mapping implements Serializable{
    private static final long serialVersionUID = 1L;
    private Map<String, String> classMap;
    private Map<String, Map<String, String>> methodMap;
    
    public Mapping() {
        classMap = new HashMap<>();
        methodMap = new HashMap<>();
    }
    
    /**
     * Get the class mapping.
     * 
     * @return the map contains all class mapping info
     */
    public Map<String, String> getClassMap() {
        return classMap;
    }

    /**
     * Get the method mapping.
     * 
     * @return the map contains all method mapping info
     */
    public Map<String, Map<String, String>> getMethodMap() {
        return methodMap;
    }
}
