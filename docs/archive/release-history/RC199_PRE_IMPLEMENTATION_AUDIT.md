# RC199: Pre-Implementation Design Audit

## 1. Metadata Verification
We audited the availability of all metadata structures inside `GlobalSymbolTable` and `Program`:
- **Field Annotations**: Available in `FieldInfo.annotations: Vec<String>`.
- **Constructor Parameter Metadata**: Available in `MethodInfo.parameters: Vec<String>`.
- **Interface Implementation Index**: Available via `gst.interface_to_implementors: HashMap<String, HashSet<TypeId>>`.
- **Inheritance Index**: Available via `gst.child_to_parent: HashMap<TypeId, String>` and `get_all_subclasses`.
- **Declaring Type Information**: Available via `MethodInfo.parent_type_id: Option<TypeId>`.
- **Method Ownership Information**: Map `MethodId` directly to `MethodInfo` containing `parent_type_id`.

No new global indexes are required; the existing indices cover all lookup cases.

---

## 2. Constructor Injection Detection
Constructor parameter-to-field assignment can be statically recovered by:
1. Locating the class constructor (`<init>`).
2. Iterating through its `Assign` instructions:
   - Identify assignments where `dest` matches `this.fieldName` (or `fieldName` matching a class field) and `src` matches one of the constructor parameter names.
3. Mapping the field name to the constructor parameter's declared type.

This allows robust mapping of constructor-injected fields without annotations.

---

## 3. Multiple Implementation Resolution Matrix

| Scenario | Resolution Strategy | Acceptability |
| :--- | :--- | :---: |
| **@Primary / @Qualifier** | Conservative over-approximation (add edges to all candidate implementations) | **B. Acceptable** |
| **Abstract classes** | Traverse subclass hierarchy to find leaf implementing classes | **A. Sufficient** |
| **Generic interfaces** | Match interface type bounds in `gst.interface_to_implementors` | **A. Sufficient** |
| **Nested implementations**| Standard type resolution via FQN paths | **A. Sufficient** |

---

## 4. Inherited Injected Fields
Inherited injected fields are not directly listed under the subclass's fields. To resolve them:
- When a field lookup fails on the target class, walk up the inheritance chain using the `parent_type` of the class until the field declaration is found.
This is implemented entirely within the field type resolution step of `call_graph.rs`.
