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
package com.pnf.androsig.apply.model;

/**
 * Definition of one library signature info.
 * 
 * @author Ruoxiao Wang
 *
 */
public class LibraryInfo {
    private String author;
    private int version;
    private String libName;

    /**
     * Get the author of the library signature file.
     * 
     * @return the author of the library signature file
     */
    public String getAuthor() {
        return author;
    }

    /**
     * Set the author of the library signature file.
     * 
     */
    public void setAuthor(String author) {
        this.author = author;
    }

    /**
     * Get the version of the library signature file.
     * 
     * @return the version of the library signature file
     */
    public int getVersion() {
        return version;
    }

    /**
     * Set the version of the library signature file.
     * 
     */
    public void setVersion(int version) {
        this.version = version;
    }

    /**
     * Get the name of the library signature file.
     * 
     * @return the name of the library signature file
     */
    public String getLibName() {
        return libName;
    }

    /**
     * Set the name of the library signature file.
     * 
     */
    public void setLibName(String libName) {
        this.libName = libName;
    }
}
